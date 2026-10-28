package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ovsec/hush/internal/crypt"
)

func init() { crypt.DefaultKDF = crypt.KDFParams{Alg: "argon2id", Time: 1, MemKiB: 1024, Threads: 1} }

const pass = "correct horse battery"

func newVault(t *testing.T) *Service {
	t.Helper()
	s := New(t.TempDir())
	if err := s.Create("team", "ada", []byte(pass)); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCreateSaveRevealAcrossRestart(t *testing.T) {
	s := newVault(t)
	id, err := s.Save("", Entry{Title: "github", Username: "ada", Password: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	s.Lock()
	if _, err := s.Reveal(id); err != ErrLocked {
		t.Fatal("locked vault must not reveal")
	}

	again := New(s.Dir())
	if err := again.Unlock([]byte("nope")); err != ErrBadPassphrase {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if err := again.Unlock([]byte(pass)); err != nil {
		t.Fatal(err)
	}
	e, err := again.Reveal(id)
	if err != nil || e.Password != "s3cret" {
		t.Fatalf("reveal: %+v %v", e, err)
	}
	if items := again.Items(); len(items) != 1 || items[0].Author != "you" {
		t.Fatalf("items: %+v", items)
	}
}

func TestEditAndDelete(t *testing.T) {
	s := newVault(t)
	id, _ := s.Save("", Entry{Title: "aws", Password: "one"})
	if _, err := s.Save(id, Entry{Title: "aws", Password: "two"}); err != nil {
		t.Fatal(err)
	}
	if e, _ := s.Reveal(id); e.Password != "two" {
		t.Fatal("edit not applied")
	}
	if it := s.Items()[0]; it.Version != 2 {
		t.Fatalf("version %d", it.Version)
	}
	if err := s.Delete(id); err != nil {
		t.Fatal(err)
	}
	s.Lock()
	if err := s.Unlock([]byte(pass)); err != nil {
		t.Fatal(err)
	}
	if len(s.Items()) != 0 {
		t.Fatal("deleted secret came back")
	}
}

func TestNothingSecretOnDisk(t *testing.T) {
	s := newVault(t)
	s.Save("", Entry{Title: "prod-db", Username: "app_rw", Password: "hunter2-very-secret"})
	for _, f := range []string{IdentityFile, OpsFile} {
		b, _ := os.ReadFile(filepath.Join(s.Dir(), f))
		for _, word := range []string{"prod-db", "app_rw", "hunter2", pass} {
			if strings.Contains(string(b), word) {
				t.Fatalf("%s contains %q in the clear", f, word)
			}
		}
	}
}

func TestTamperedLogRefusesToUnlock(t *testing.T) {
	s := newVault(t)
	s.Save("", Entry{Title: "x", Password: "y"})
	s.Lock()
	path := filepath.Join(s.Dir(), OpsFile)
	b, _ := os.ReadFile(path)
	os.WriteFile(path, []byte(strings.Replace(string(b), `"clock":3`, `"clock":4`, 1)), 0o600)
	if err := s.Unlock([]byte(pass)); err == nil || !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("tampered log: %v", err)
	}
}

func TestInfoWhileLocked(t *testing.T) {
	s := newVault(t)
	s.Save("", Entry{Title: "a"})
	s.Lock()
	info, err := s.Info()
	if err != nil {
		t.Fatal(err)
	}
	if info.Vault != "team" || info.Me != "ada" || info.Secrets != 1 || info.Unlocked {
		t.Fatalf("%+v", info)
	}
}
