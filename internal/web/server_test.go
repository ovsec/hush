package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ovsec/hush/internal/app"
	"github.com/ovsec/hush/internal/crypt"
)

func init() { crypt.DefaultKDF = crypt.KDFParams{Alg: "argon2id", Time: 1, MemKiB: 1024, Threads: 1} }

const host = "127.0.0.1:7777"

type client struct {
	t      *testing.T
	h      http.Handler
	cookie *http.Cookie
}

func setup(t *testing.T) (*client, *app.Service) {
	svc := app.New(t.TempDir())
	if err := svc.Create("team", "ada", []byte("correct horse")); err != nil {
		t.Fatal(err)
	}
	svc.Lock()
	s := New(svc)
	s.host, s.token = host, "launch"
	return &client{t: t, h: s.routes()}, svc
}

func (c *client) do(method, path, body string, mod func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = host
	if c.cookie != nil {
		r.AddCookie(c.cookie)
	}
	if method != http.MethodGet {
		r.Header.Set("X-Hush", "1")
		r.Header.Set("Origin", "http://"+host)
	}
	if mod != nil {
		mod(r)
	}
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, r)
	return w
}

func (c *client) login() {
	w := c.do("GET", "/?t=launch", "", nil)
	if w.Code != http.StatusSeeOther {
		c.t.Fatalf("launch: %d", w.Code)
	}
	c.cookie = w.Result().Cookies()[0]
}

func TestLaunchTokenIsSingleUse(t *testing.T) {
	c, _ := setup(t)
	if w := c.do("GET", "/api/state", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("no session: %d", w.Code)
	}
	c.login()
	if !c.cookie.HttpOnly || c.cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("session cookie must be HttpOnly and SameSite=Strict")
	}
	if w := c.do("GET", "/?t=launch", "", nil); w.Code != http.StatusForbidden {
		t.Fatalf("reused token: %d", w.Code)
	}
	if w := c.do("GET", "/api/state", "", nil); w.Code != http.StatusOK {
		t.Fatalf("with session: %d", w.Code)
	}
}

func TestRefusesForeignHostAndCrossSite(t *testing.T) {
	c, _ := setup(t)
	c.login()
	if w := c.do("GET", "/api/state", "", func(r *http.Request) { r.Host = "evil.example:7777" }); w.Code != http.StatusMisdirectedRequest {
		t.Fatalf("rebinding host: %d", w.Code)
	}
	if w := c.do("POST", "/api/lock", "", func(r *http.Request) { r.Header.Del("X-Hush") }); w.Code != http.StatusForbidden {
		t.Fatalf("missing X-Hush: %d", w.Code)
	}
	if w := c.do("POST", "/api/lock", "", func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }); w.Code != http.StatusForbidden {
		t.Fatalf("foreign origin: %d", w.Code)
	}
	w := c.do("GET", "/", "", nil)
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatal("missing CSP")
	}
}

func TestUnlockSaveReveal(t *testing.T) {
	c, _ := setup(t)
	c.login()
	if w := c.do("GET", "/api/items", "", nil); w.Code != http.StatusLocked {
		t.Fatalf("locked items: %d", w.Code)
	}
	if w := c.do("POST", "/api/unlock", `{"passphrase":"nope"}`, nil); w.Code != http.StatusForbidden {
		t.Fatalf("bad passphrase: %d", w.Code)
	}
	if w := c.do("POST", "/api/unlock", `{"passphrase":"correct horse"}`, nil); w.Code != http.StatusOK {
		t.Fatalf("unlock: %d %s", w.Code, w.Body)
	}
	w := c.do("POST", "/api/items", `{"entry":{"title":"github","password":"s3cret"}}`, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	list := c.do("GET", "/api/items", "", nil).Body.String()
	if strings.Contains(list, "s3cret") || !strings.Contains(list, "github") {
		t.Fatalf("list must not carry passwords: %s", list)
	}
	id := strings.Split(strings.Split(w.Body.String(), `"id":"`)[1], `"`)[0]
	if body := c.do("GET", "/api/items/"+id, "", nil).Body.String(); !strings.Contains(body, "s3cret") {
		t.Fatalf("reveal: %s", body)
	}
}
