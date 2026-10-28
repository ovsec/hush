package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/ovsec/hush/internal/sso"
	"github.com/ovsec/hush/internal/vault"
)

// joinMaxAge is how long after signing in a joiner can still be added.
const joinMaxAge = 7 * 24 * time.Hour

// LinkLogin signs in with a company OIDC provider and stores the ID token,
// bound to this identity's keys, so it travels in the join code.
func (s *Service) LinkLogin(ctx context.Context, issuer, clientID string, open func(string) error) (sso.Claims, error) {
	s.mu.Lock()
	disk, err := s.readIdentity()
	s.mu.Unlock()
	if err != nil {
		return sso.Claims{}, err
	}
	nonce := sso.Nonce(disk.Sign, disk.Box)
	s.feed.Emit("sso", "nonce = sha-256 of your public keys · binds this login to them")
	s.feed.Emit("sso", "authorization code + PKCE (S256) · callback on 127.0.0.1 · signing in at %s", hostOf(issuer))
	raw, c, err := sso.Login{Issuer: issuer, ClientID: clientID, Open: open}.Run(ctx, nonce)
	if err != nil {
		s.feed.Emit("deny", "company login failed: %v", err)
		return sso.Claims{}, err
	}
	s.feed.Emit("verify", "id token from %s · signature, audience and nonce ok · %s", hostOf(c.Issuer), c.Email)

	s.mu.Lock()
	defer s.mu.Unlock()
	disk, err = s.readIdentity()
	if err != nil {
		return sso.Claims{}, err
	}
	disk.IDToken = raw
	b, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return sso.Claims{}, err
	}
	if err := writeFileAtomic(filepath.Join(s.dir, IdentityFile), b, 0o600); err != nil {
		return sso.Claims{}, err
	}
	s.feed.Emit("write", "%s · login stored · it travels in your join code (valid %s)", IdentityFile, joinMaxAge)
	return c, nil
}

// LoginEmail is the email in this identity's stored login, unverified; "" if none.
func (s *Service) LoginEmail() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	disk, err := s.readIdentity()
	if err != nil || disk.IDToken == "" {
		return ""
	}
	parts := strings.Split(disk.IDToken, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		Email string `json:"email"`
		User  string `json:"preferred_username"`
	}
	json.Unmarshal(payload, &c)
	if c.Email != "" {
		return c.Email
	}
	return c.User
}

// SetLoginPolicy sets which company login new members must (or may) prove.
// An empty issuer turns it off.
func (s *Service) SetLoginPolicy(p vault.SSOPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.me == nil {
		return ErrLocked
	}
	if !s.state.IsAdmin(s.me.ID()) {
		return ErrNotAdmin
	}
	if p.Issuer != "" && p.ClientID == "" {
		return errors.New("a login policy needs the client id registered with the provider")
	}
	if _, err := s.commit(vault.KindSSO, p); err != nil {
		return err
	}
	if p.Issuer == "" {
		s.feed.Emit("policy", "company login policy removed")
	} else {
		s.feed.Emit("policy", "new members %s sign in at %s · allowed: %s", map[bool]string{true: "must", false: "may"}[p.Require], hostOf(p.Issuer), allowList(p.Allow))
	}
	return nil
}

// LoginPolicy is the vault's company login policy, or nil. Works locked.
func (s *Service) LoginPolicy() (*vault.SSOPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.state
	if st == nil {
		var err error
		if st, err = s.load(false); err != nil {
			return nil, err
		}
	}
	return st.SSO, nil
}

// JoinCheck is what an admin sees before adding someone.
type JoinCheck struct {
	Name   string             `json:"name"`
	Safety string             `json:"safety"`
	SSO    *vault.SSOIdentity `json:"sso,omitempty"`
	Note   string             `json:"note,omitempty"`
}

// CheckJoin parses a join code and, under a login policy, verifies the
// company login it carries. It talks to the provider, so it takes a context.
func (s *Service) CheckJoin(ctx context.Context, code string) (JoinCheck, error) {
	r, err := ParseJoinCode(code)
	if err != nil {
		return JoinCheck{}, err
	}
	jc := JoinCheck{Name: r.Name, Safety: r.Safety()}
	pol, err := s.LoginPolicy()
	if err != nil {
		return jc, err
	}
	switch {
	case pol == nil && r.Tok == "":
		return jc, nil
	case pol == nil:
		jc.Note = "their code carries a company login, but this vault has no login policy, so it was not checked"
		return jc, nil
	case r.Tok == "" && pol.Require:
		return jc, fmt.Errorf("this vault requires a company login: ask %s to run hush login first", r.Name)
	case r.Tok == "":
		jc.Note = "no company login in their code; rely on the safety number"
		return jc, nil
	}
	c, err := sso.Verify(ctx, pol.Issuer, pol.ClientID, r.Tok, sso.Nonce(r.Sign, r.Box), joinMaxAge)
	if err != nil {
		s.feed.Emit("deny", "company login for %q did not verify: %v", r.Name, err)
		return jc, fmt.Errorf("company login did not verify: %w", err)
	}
	if c.EmailVerified != nil && !*c.EmailVerified {
		return jc, fmt.Errorf("%s has not verified that email with the provider", c.Email)
	}
	if !sso.Allowed(c.Email, pol.Allow) {
		return jc, fmt.Errorf("%s is not allowed by this vault's login policy (%s)", c.Email, allowList(pol.Allow))
	}
	jc.SSO = &vault.SSOIdentity{Issuer: c.Issuer, Subject: c.Subject, Email: c.Email}
	s.feed.Emit("verify", "%q signed in as %s at %s · token bound to their keys · %s old", r.Name, c.Email, hostOf(c.Issuer), time.Since(c.IssuedAt).Round(time.Minute))
	return jc, nil
}

func allowList(a []string) string {
	if len(a) == 0 {
		return "anyone the provider vouches for"
	}
	return strings.Join(a, ", ")
}

func hostOf(issuer string) string {
	h := strings.TrimPrefix(strings.TrimPrefix(issuer, "https://"), "http://")
	if i := strings.IndexByte(h, '/'); i > 0 {
		h = h[:i]
	}
	return h
}
