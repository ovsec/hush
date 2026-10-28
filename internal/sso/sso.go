// Package sso binds a member's keys to a company login. The joiner signs in
// with OIDC (authorization code + PKCE, loopback redirect) and the request's
// nonce is a hash of their public keys, so the ID token the provider signs
// says "this person asked for these exact keys". The admin verifies it.
package sso

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Claims is what hush keeps from an ID token.
type Claims struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified *bool
	IssuedAt      time.Time
}

// Nonce binds a login to a member's public keys.
func Nonce(signPub, boxPub string) string {
	sum := sha256.Sum256([]byte("hush/sso/v1|" + signPub + "|" + boxPub))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Login runs the authorization code flow with PKCE.
type Login struct {
	Issuer   string
	ClientID string
	// Open shows the user the provider's sign-in page, normally a browser.
	Open func(url string) error
}

// Run signs in and returns the raw ID token and its verified claims.
func (l Login) Run(ctx context.Context, nonce string) (string, Claims, error) {
	provider, err := oidc.NewProvider(ctx, l.Issuer)
	if err != nil {
		return "", Claims{}, fmt.Errorf("discovering %s: %w", l.Issuer, err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", Claims{}, err
	}
	defer ln.Close()

	conf := oauth2.Config{
		ClientID:    l.ClientID,
		Endpoint:    provider.Endpoint(),
		RedirectURL: "http://" + ln.Addr().String() + "/callback",
		Scopes:      []string{oidc.ScopeOpenID, "email", "profile"},
	}
	verifier, state := oauth2.GenerateVerifier(), randomString()

	type result struct {
		code string
		err  error
	}
	done := make(chan result, 1)
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		res := result{code: q.Get("code")}
		switch {
		case q.Get("state") != state:
			res.err = errors.New("sign-in response did not match this request")
		case q.Get("error") != "":
			res.err = fmt.Errorf("provider said %s: %s", q.Get("error"), q.Get("error_description"))
		case res.code == "":
			res.err = errors.New("provider returned no code")
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if res.err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "hush: sign-in failed:", res.err)
		} else {
			fmt.Fprintln(w, "hush: signed in. You can close this tab and go back to hush.")
		}
		select {
		case done <- res:
		default:
		}
	})}
	go srv.Serve(ln)
	defer srv.Close()

	url := conf.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce))
	if err := l.Open(url); err != nil {
		return "", Claims{}, err
	}
	var res result
	select {
	case <-ctx.Done():
		return "", Claims{}, ctx.Err()
	case res = <-done:
	}
	if res.err != nil {
		return "", Claims{}, res.err
	}
	tok, err := conf.Exchange(ctx, res.code, oauth2.VerifierOption(verifier))
	if err != nil {
		return "", Claims{}, fmt.Errorf("exchanging the code: %w", err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return "", Claims{}, errors.New("provider returned no id token")
	}
	c, err := Verify(ctx, l.Issuer, l.ClientID, raw, nonce, time.Hour)
	return raw, c, err
}

// Verify checks an ID token's signature, issuer, audience and nonce. Tokens
// expire within the hour but an admin may add someone days later, so expiry
// is replaced by a maximum age since the login.
func Verify(ctx context.Context, issuer, clientID, raw, nonce string, maxAge time.Duration) (Claims, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return Claims{}, fmt.Errorf("discovering %s: %w", issuer, err)
	}
	idt, err := provider.Verifier(&oidc.Config{ClientID: clientID, SkipExpiryCheck: true}).Verify(ctx, raw)
	if err != nil {
		return Claims{}, err
	}
	if idt.Nonce != nonce {
		return Claims{}, errors.New("the login is not bound to these keys")
	}
	if age := time.Since(idt.IssuedAt); age > maxAge {
		return Claims{}, fmt.Errorf("the login is %s old; ask them to sign in again", age.Round(time.Hour))
	}
	var extra struct {
		Email             string `json:"email"`
		EmailVerified     *bool  `json:"email_verified"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idt.Claims(&extra); err != nil {
		return Claims{}, err
	}
	email := extra.Email
	if email == "" {
		email = extra.PreferredUsername // Entra ID
	}
	return Claims{Issuer: idt.Issuer, Subject: idt.Subject, Email: email, EmailVerified: extra.EmailVerified, IssuedAt: idt.IssuedAt}, nil
}

// Allowed checks an email against addresses and "@domain" entries. An empty
// list allows anyone the provider vouches for.
func Allowed(email string, allow []string) bool {
	if len(allow) == 0 {
		return true
	}
	e := strings.ToLower(strings.TrimSpace(email))
	for _, a := range allow {
		a = strings.ToLower(strings.TrimSpace(a))
		if (strings.HasPrefix(a, "@") && strings.HasSuffix(e, a)) || e == a {
			return true
		}
	}
	return false
}

func randomString() string {
	b := make([]byte, 24)
	rand.Read(b)
	return hex.EncodeToString(b)
}
