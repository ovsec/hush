// Package ssotest is a minimal OIDC provider for tests: discovery, JWKS, an
// authorize endpoint that signs the user in at once, and a token endpoint
// that enforces PKCE.
package ssotest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// IdP is a running test provider.
type IdP struct {
	*httptest.Server
	ClientID string
	Email    string // who signs in next
	Subject  string

	key   *rsa.PrivateKey
	mu    sync.Mutex
	codes map[string]grant
}

type grant struct{ nonce, challenge, redirect string }

// New starts a provider; Close it when done.
func New(clientID, email string) *IdP {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	p := &IdP{ClientID: clientID, Email: email, Subject: "user-" + email, key: key, codes: map[string]grant{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("/keys", p.keys)
	mux.HandleFunc("/authorize", p.authorize)
	mux.HandleFunc("/token", p.token)
	p.Server = httptest.NewServer(mux)
	return p
}

// Browser stands in for the user's browser: it follows the redirect back to
// hush's loopback listener.
func Browser(u string) error {
	resp, err := http.Get(u)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func (p *IdP) discovery(w http.ResponseWriter, _ *http.Request) {
	json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                p.URL,
		"authorization_endpoint":                p.URL + "/authorize",
		"token_endpoint":                        p.URL + "/token",
		"jwks_uri":                              p.URL + "/keys",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (p *IdP) keys(w http.ResponseWriter, _ *http.Request) {
	json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &p.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
}

func (p *IdP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != p.ClientID || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	code := hex.EncodeToString(make([]byte, 4)) + time.Now().Format("150405.000000000")
	p.mu.Lock()
	p.codes[code] = grant{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri")}
	p.mu.Unlock()
	back, _ := url.Parse(q.Get("redirect_uri"))
	v := back.Query()
	v.Set("code", code)
	v.Set("state", q.Get("state"))
	back.RawQuery = v.Encode()
	http.Redirect(w, r, back.String(), http.StatusFound)
}

func (p *IdP) token(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	p.mu.Lock()
	g, ok := p.codes[r.Form.Get("code")]
	delete(p.codes, r.Form.Get("code"))
	p.mu.Unlock()
	sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
	if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge || r.Form.Get("redirect_uri") != g.redirect {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}
	idToken, err := p.Sign(g.nonce, time.Now())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600, "id_token": idToken})
}

// Sign issues an ID token for the current Email with this nonce.
func (p *IdP) Sign(nonce string, issued time.Time) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: p.key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	if err != nil {
		return "", err
	}
	return jwt.Signed(signer).Claims(map[string]any{
		"iss": p.URL, "sub": p.Subject, "aud": p.ClientID, "nonce": nonce,
		"iat": issued.Unix(), "exp": issued.Add(time.Hour).Unix(),
		"email": p.Email, "email_verified": true,
	}).Serialize()
}
