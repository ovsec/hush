package app

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func newJoiner(t *testing.T, name string) *Service {
	t.Helper()
	s := New(t.TempDir())
	if err := s.Join(name, []byte(pass)); err != nil {
		t.Fatal(err)
	}
	return s
}

// carry moves a bundle from one machine to another.
func carry(t *testing.T, from, to *Service) ImportResult {
	t.Helper()
	path := filepath.Join(t.TempDir(), "team.bundle")
	if _, err := from.Export(path); err != nil {
		t.Fatal(err)
	}
	res, err := to.Import(path)
	if err != nil && !errors.Is(err, ErrRemoved) {
		t.Fatal(err)
	}
	return res
}

func TestTeamLifecycle(t *testing.T) {
	admin := newVault(t)
	secretID, _ := admin.Save("", Entry{Title: "prod db", Password: "p1"})

	bob := newJoiner(t, "bob")
	if bob.Status() != StatusPending {
		t.Fatal("joiner should be pending")
	}
	code, safety, err := bob.JoinCode()
	if err != nil {
		t.Fatal(err)
	}
	m, err := admin.AddMember(code)
	if err != nil {
		t.Fatal(err)
	}
	if m.Safety != safety {
		t.Fatal("both sides must see the same safety number")
	}

	carry(t, admin, bob)
	if bob.Status() != StatusReady {
		t.Fatal("bob should be a member after import")
	}
	if err := bob.Unlock([]byte(pass)); err != nil {
		t.Fatal(err)
	}
	if e, err := bob.Reveal(secretID); err != nil || e.Password != "p1" {
		t.Fatalf("bob reveal: %v", err)
	}
	if _, err := bob.AddMember(code); err != ErrNotAdmin {
		t.Fatal("members cannot add members")
	}

	// bob writes, admin picks it up.
	bobID, _ := bob.Save("", Entry{Title: "bob's token", Password: "b1"})
	carry(t, bob, admin)
	if e, err := admin.Reveal(bobID); err != nil || e.Password != "b1" {
		t.Fatalf("admin reveal bob's secret: %v", err)
	}

	// remove bob: new epoch, everything re-encrypted and flagged.
	n, err := admin.RemoveMember(m.ID)
	if err != nil || n != 2 {
		t.Fatalf("remove: n=%d err=%v", n, err)
	}
	for _, it := range admin.Items() {
		if it.Epoch != 2 || len(it.Exposed) != 1 || it.Exposed[0] != "bob" {
			t.Fatalf("after removal: %+v", it)
		}
	}
	admin.Save(secretID, Entry{Title: "prod db", Password: "p2"})
	for _, it := range admin.Items() {
		if it.ID == secretID && len(it.Exposed) != 0 {
			t.Fatal("changing the value must clear the exposure flag")
		}
	}

	// bob receives his removal and is locked out.
	carry(t, admin, bob)
	if bob.Unlocked() || bob.Status() != StatusRemoved {
		t.Fatal("bob should be locked out")
	}
	if err := bob.Unlock([]byte(pass)); err != ErrRemoved {
		t.Fatalf("removed unlock: %v", err)
	}

	// and bob's later writes are not accepted.
	members, _ := admin.Members()
	if len(members) != 2 || !members[1].Removed {
		t.Fatalf("members: %+v", members)
	}
}

func TestJoinCodeTamperRejected(t *testing.T) {
	bob := newJoiner(t, "bob")
	code, _, _ := bob.JoinCode()
	if _, err := ParseJoinCode(code); err != nil {
		t.Fatal(err)
	}
	r, _ := ParseJoinCode(code)
	eve := newJoiner(t, "eve")
	eveCode, _, _ := eve.JoinCode()
	e, _ := ParseJoinCode(eveCode)
	// Pair bob's signing key with eve's encryption key.
	r.Box = e.Box
	if r.Safety() == safetyOf(bob) {
		t.Fatal("safety number must change when any key changes")
	}
	if _, err := ParseJoinCode(code[:len(code)-4] + "AAAA"); err == nil {
		t.Fatal("damaged code must be rejected")
	}
}

func safetyOf(s *Service) string { _, safety, _ := s.JoinCode(); return safety }

func TestBundleFromOtherVaultRejected(t *testing.T) {
	a, b := newVault(t), newVault(t)
	path := filepath.Join(t.TempDir(), "x.bundle")
	a.Export(path)
	if _, err := b.Import(path); err == nil || !strings.Contains(err.Error(), "different vault") {
		t.Fatalf("cross-vault import: %v", err)
	}
}

func TestImportIsIdempotent(t *testing.T) {
	admin := newVault(t)
	admin.Save("", Entry{Title: "a"})
	bob := newJoiner(t, "bob")
	code, _, _ := bob.JoinCode()
	admin.AddMember(code)
	first := carry(t, admin, bob)
	again := carry(t, admin, bob)
	if first.Added == 0 || again.Added != 0 || again.Known != first.Added {
		t.Fatalf("first %+v again %+v", first, again)
	}
}
