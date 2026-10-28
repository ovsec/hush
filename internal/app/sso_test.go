package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ovsec/hush/internal/sso/ssotest"
	"github.com/ovsec/hush/internal/vault"
)

func linked(t *testing.T, idp *ssotest.IdP, name, email string) *Service {
	t.Helper()
	s := newJoiner(t, name)
	idp.Email, idp.Subject = email, "sub-"+email
	c, err := s.LinkLogin(context.Background(), idp.URL, idp.ClientID, ssotest.Browser)
	if err != nil {
		t.Fatal(err)
	}
	if c.Email != email || s.LoginEmail() != email {
		t.Fatalf("linked %q, stored %q", c.Email, s.LoginEmail())
	}
	return s
}

func code(s *Service) string { c, _, _ := s.JoinCode(); return c }

func TestCompanyLoginGatesJoining(t *testing.T) {
	idp := ssotest.New("hush", "")
	defer idp.Close()
	admin := newVault(t)
	if err := admin.SetLoginPolicy(vault.SSOPolicy{Issuer: idp.URL, ClientID: "hush", Allow: []string{"@co.com"}, Require: true}); err != nil {
		t.Fatal(err)
	}

	alice := linked(t, idp, "alice", "alice@co.com")
	check, err := admin.CheckJoin(context.Background(), code(alice))
	if err != nil || check.SSO == nil || check.SSO.Email != "alice@co.com" {
		t.Fatalf("check: %+v %v", check, err)
	}
	m, err := admin.AddMember(code(alice))
	if err != nil || m.SSO == nil {
		t.Fatalf("add: %+v %v", m, err)
	}
	if _, err := admin.AddMember(code(linked(t, idp, "alice2", "alice@co.com"))); err == nil || !strings.Contains(err.Error(), "already a member") {
		t.Fatalf("same login twice: %v", err)
	}

	if _, err := admin.AddMember(code(newJoiner(t, "nologin"))); err == nil || !strings.Contains(err.Error(), "requires a company login") {
		t.Fatalf("no login: %v", err)
	}
	if _, err := admin.AddMember(code(linked(t, idp, "mallory", "mallory@evil.com"))); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("wrong domain: %v", err)
	}

	// A stolen login pasted into someone else's join code fails the nonce.
	eve := newJoiner(t, "eve")
	var stolen, eves JoinRequest
	decodeCode(t, code(alice), &stolen)
	decodeCode(t, code(eve), &eves)
	eves.Tok = stolen.Tok
	b, _ := json.Marshal(eves)
	if _, err := admin.AddMember(joinPrefix + base64.RawURLEncoding.EncodeToString(b)); err == nil || !strings.Contains(err.Error(), "not bound to these keys") {
		t.Fatalf("stolen token: %v", err)
	}

	members, _ := admin.Members()
	for _, mem := range members {
		if mem.Name == "alice" && (mem.SSO == nil || mem.SSO.Email != "alice@co.com") {
			t.Fatalf("alice's verified login not recorded: %+v", mem)
		}
	}
}

func decodeCode(t *testing.T, c string, r *JoinRequest) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(c, joinPrefix))
	if err != nil || json.Unmarshal(b, r) != nil {
		t.Fatal("bad code")
	}
}
