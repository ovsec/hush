// Package web serves hush's local browser UI. It listens on 127.0.0.1 only,
// lets a browser in through a one-time launch token, and talks JSON to the
// same app.Service the TUI uses. Keys never leave this process.
package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ovsec/hush/internal/app"
)

//go:embed static
var static embed.FS

const (
	cookieName = "hush_session"
	autoLock   = 5 * time.Minute
	maxBody    = 8 << 20
)

const csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// Server is one local web UI session.
type Server struct {
	svc  *app.Service
	host string

	mu      sync.Mutex
	token   string
	session string
	idle    time.Time
}

// New prepares a server for svc.
func New(svc *app.Service) *Server { return &Server{svc: svc, idle: time.Now()} }

// Run listens on 127.0.0.1:port (0 picks a free port), calls ready with the
// launch URL, and serves until ctx is done.
func (s *Server) Run(ctx context.Context, port int, ready func(url string)) error {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	s.host = ln.Addr().String()
	s.token = randHex(32)
	srv := &http.Server{
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	go s.lockWhenIdle(ctx)
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(shut)
	}()
	s.svc.Feed().Emit("web", "listening on %s only · one-time launch token issued", s.host)
	ready("http://" + s.host + "/?t=" + s.token)
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	s.svc.Lock()
	return nil
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(static, "static")
	mux.HandleFunc("GET /{$}", s.index)
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(sub)))
	mux.HandleFunc("GET /api/events", s.events)

	mux.HandleFunc("GET /api/state", s.api(s.state))
	mux.HandleFunc("POST /api/unlock", s.api(s.unlock))
	mux.HandleFunc("POST /api/lock", s.api(s.lock))
	mux.HandleFunc("GET /api/items", s.api(s.items))
	mux.HandleFunc("POST /api/items", s.api(s.save))
	mux.HandleFunc("GET /api/items/{id}", s.api(s.reveal))
	mux.HandleFunc("DELETE /api/items/{id}", s.api(s.delete))
	mux.HandleFunc("GET /api/items/{id}/raw", s.api(s.raw))
	mux.HandleFunc("POST /api/generate", s.api(s.generate))
	mux.HandleFunc("POST /api/clip", s.api(s.clip))
	mux.HandleFunc("GET /api/members", s.api(s.members))
	mux.HandleFunc("POST /api/members/check", s.api(s.checkCode))
	mux.HandleFunc("POST /api/members", s.api(s.addMember))
	mux.HandleFunc("DELETE /api/members/{id}", s.api(s.removeMember))
	mux.HandleFunc("GET /api/bundle", s.bundle)
	mux.HandleFunc("POST /api/import", s.api(s.importBundle))
	return s.guard(mux)
}

// guard rejects requests for any other host name (DNS rebinding) and sets
// headers that keep the page out of frames, caches and referrers.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != s.host {
			http.Error(w, "wrong host", http.StatusMisdirectedRequest)
			return
		}
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// index trades the one-time launch token for a session cookie.
func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if t := r.URL.Query().Get("t"); t != "" {
		s.mu.Lock()
		ok := s.token != "" && subtle.ConstantTimeCompare([]byte(t), []byte(s.token)) == 1
		if ok {
			s.token, s.session = "", randHex(32)
		}
		session := s.session
		s.mu.Unlock()
		if !ok {
			http.Error(w, "This link was already used. Run hush web again for a new one.", http.StatusForbidden)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: session, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
		s.svc.Feed().Emit("web", "browser admitted · launch token spent · session cookie set (HttpOnly, SameSite=Strict)")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if !s.authed(r) {
		http.Error(w, "Open the link printed by hush web.", http.StatusUnauthorized)
		return
	}
	b, _ := static.ReadFile("static/index.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(b)
}

func (s *Server) authed(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	s.mu.Lock()
	defer s.mu.Unlock()
	return err == nil && s.session != "" && subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.session)) == 1
}

// allowed checks the session and, for anything that changes state, that the
// request came from our own page.
func (s *Server) allowed(w http.ResponseWriter, r *http.Request) bool {
	if !s.authed(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in; open the link printed by hush web"})
		return false
	}
	if r.Method != http.MethodGet {
		origin := r.Header.Get("Origin")
		if r.Header.Get("X-Hush") != "1" || (origin != "" && origin != "http://"+s.host) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request refused"})
			return false
		}
	}
	s.mu.Lock()
	s.idle = time.Now()
	s.mu.Unlock()
	return true
}

type handler func(r *http.Request) (any, error)

func (s *Server) api(fn handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.allowed(w, r) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		v, err := fn(r)
		if err != nil {
			writeJSON(w, statusFor(err), map[string]string{"error": err.Error()})
			return
		}
		if v == nil {
			v = map[string]bool{"ok": true}
		}
		writeJSON(w, http.StatusOK, v)
	}
}

func statusFor(err error) int {
	switch {
	case errors.Is(err, app.ErrLocked):
		return http.StatusLocked
	case errors.Is(err, app.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, app.ErrNotAdmin), errors.Is(err, app.ErrRemoved), errors.Is(err, app.ErrBadPassphrase):
		return http.StatusForbidden
	}
	return http.StatusBadRequest
}

func (s *Server) lockWhenIdle(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.mu.Lock()
			idle := time.Since(s.idle)
			s.mu.Unlock()
			if idle > autoLock && s.svc.Unlocked() {
				s.svc.Lock()
				s.svc.Feed().Emit("lock", "locked after 5 minutes without activity")
			}
		}
	}
}

// ── handlers ────────────────────────────────────────────────────────

func decode(r *http.Request, v any) error {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return errors.New("bad request body")
	}
	return nil
}

type stateResp struct {
	Status string   `json:"status"`
	Info   app.Info `json:"info"`
	Code   string   `json:"code,omitempty"`
	Safety string   `json:"safety,omitempty"`
	// Online and Others count other members; Syncing is false when sync is off.
	Online  int  `json:"online"`
	Others  int  `json:"others"`
	Syncing bool `json:"syncing"`
}

func (s *Server) state(*http.Request) (any, error) {
	resp := stateResp{Status: [...]string{"none", "pending", "ready", "removed"}[s.svc.Status()]}
	resp.Info, _ = s.svc.Info()
	if resp.Status == "pending" {
		resp.Code, resp.Safety, _ = s.svc.JoinCode()
	}
	if resp.Info.Unlocked {
		members, _ := s.svc.Members()
		for _, m := range members {
			if m.You || m.Removed {
				continue
			}
			resp.Others++
			resp.Syncing = resp.Syncing || m.Presence != ""
			if m.Presence == "direct" || m.Presence == "relay" {
				resp.Online++
			}
		}
	}
	return resp, nil
}

func (s *Server) unlock(r *http.Request) (any, error) {
	var body struct {
		Passphrase string `json:"passphrase"`
	}
	if err := decode(r, &body); err != nil {
		return nil, err
	}
	if err := s.svc.Unlock([]byte(body.Passphrase)); err != nil {
		return nil, err
	}
	return s.state(r)
}

func (s *Server) lock(*http.Request) (any, error) {
	s.svc.Lock()
	return nil, nil
}

func (s *Server) items(*http.Request) (any, error) {
	if !s.svc.Unlocked() {
		return nil, app.ErrLocked
	}
	return s.svc.Items(), nil
}

func (s *Server) reveal(r *http.Request) (any, error) { return s.svc.Reveal(r.PathValue("id")) }

func (s *Server) save(r *http.Request) (any, error) {
	var body struct {
		ID    string    `json:"id"`
		Entry app.Entry `json:"entry"`
	}
	if err := decode(r, &body); err != nil {
		return nil, err
	}
	id, err := s.svc.Save(body.ID, body.Entry)
	return map[string]string{"id": id}, err
}

func (s *Server) delete(r *http.Request) (any, error) { return nil, s.svc.Delete(r.PathValue("id")) }

func (s *Server) raw(r *http.Request) (any, error) {
	raw, err := s.svc.Raw(r.PathValue("id"))
	return map[string]string{"raw": raw}, err
}

func (s *Server) generate(*http.Request) (any, error) {
	if !s.svc.Unlocked() {
		return nil, app.ErrLocked
	}
	return map[string]string{"password": s.svc.GeneratePassword(24)}, nil
}

// clip lets the page report clipboard use, so it shows in the activity log.
func (s *Server) clip(r *http.Request) (any, error) {
	var body struct {
		Action string `json:"action"`
		Field  string `json:"field"`
		Title  string `json:"title"`
	}
	if err := decode(r, &body); err != nil {
		return nil, err
	}
	field := map[string]string{"password": "password", "username": "username", "code": "join code"}[body.Field]
	switch body.Action {
	case "copied":
		s.svc.Feed().Emit("clip", "%s of %q copied in the browser · auto-clear in 30s", field, body.Title)
	case "cleared":
		s.svc.Feed().Emit("clip", "browser clipboard cleared")
	case "kept":
		s.svc.Feed().Emit("clip", "browser tab not focused, so the clipboard could not be cleared")
	}
	return nil, nil
}

func (s *Server) members(*http.Request) (any, error) { return s.svc.Members() }

func (s *Server) checkCode(r *http.Request) (any, error) {
	var body struct {
		Code string `json:"code"`
	}
	if err := decode(r, &body); err != nil {
		return nil, err
	}
	check, err := s.svc.CheckJoin(r.Context(), body.Code)
	if err != nil {
		return nil, err
	}
	s.svc.Feed().Emit("verify", "join code from %q · self-signature ok · compare safety numbers now", check.Name)
	return check, nil
}

func (s *Server) addMember(r *http.Request) (any, error) {
	var body struct {
		Code string `json:"code"`
	}
	if err := decode(r, &body); err != nil {
		return nil, err
	}
	return s.svc.AddMember(body.Code)
}

func (s *Server) removeMember(r *http.Request) (any, error) {
	n, err := s.svc.RemoveMember(r.PathValue("id"))
	return map[string]int{"rekeyed": n}, err
}

func (s *Server) bundle(w http.ResponseWriter, r *http.Request) {
	if !s.allowed(w, r) {
		return
	}
	info, _ := s.svc.Info()
	name := "hush-" + slug(info.Vault) + ".bundle"
	b, _, err := s.svc.Bundle("browser download " + name)
	if err != nil {
		writeJSON(w, statusFor(err), map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Write(b)
}

func (s *Server) importBundle(r *http.Request) (any, error) {
	dir, err := os.MkdirTemp("", "hush-import-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "upload.bundle")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	_, err = io.Copy(f, r.Body)
	f.Close()
	if err != nil {
		return nil, errors.New("upload failed or bundle too large")
	}
	return s.svc.Import(path)
}

// events streams the activity feed as server-sent events.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	if !s.allowed(w, r) {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	ch, cancel := s.svc.Feed().Subscribe()
	defer cancel()
	w.Header().Set("Content-Type", "text/event-stream")
	send := func(e app.Event) {
		b, _ := json.Marshal(map[string]any{"at": e.At, "kind": e.Kind, "msg": e.Msg})
		fmt.Fprintf(w, "data: %s\n\n", b)
	}
	for _, e := range s.svc.Feed().Recent(60) {
		send(e)
	}
	flusher.Flush()
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e := <-ch:
			send(e)
			flusher.Flush()
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

// ── helpers ─────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func slug(s string) string {
	out := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 32
		}
		return '-'
	}, s)
	if out = strings.Trim(out, "-"); out == "" {
		return "vault"
	}
	return out
}
