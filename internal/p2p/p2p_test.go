package p2p

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/ovsec/hush/internal/app"
	"github.com/ovsec/hush/internal/crypt"
)

func init() { crypt.DefaultKDF = crypt.KDFParams{Alg: "argon2id", Time: 1, MemKiB: 1024, Threads: 1} }

const pass = "correct horse battery"

var local = Options{Listen: []string{"/ip4/127.0.0.1/tcp/0"}, Interval: 200 * time.Millisecond}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func start(t *testing.T, svc *app.Service) *Node {
	t.Helper()
	n, err := Start(svc, local)
	must(t, err)
	t.Cleanup(n.Close)
	return n
}

func connect(t *testing.T, from, to *Node) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return from.host.Connect(ctx, peer.AddrInfo{ID: to.host.ID(), Addrs: to.host.Addrs()})
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// team makes an admin vault and a member who has joined via one bundle.
func team(t *testing.T) (admin, bob *app.Service, bobID string) {
	admin = app.New(t.TempDir())
	must(t, admin.Create("team", "ada", []byte(pass)))
	bob = app.New(t.TempDir())
	must(t, bob.Join("bob", []byte(pass)))
	code, _, _ := bob.JoinCode()
	m, err := admin.AddMember(code)
	must(t, err)
	bundle := filepath.Join(t.TempDir(), "b")
	_, err = admin.Export(bundle)
	must(t, err)
	_, err = bob.Import(bundle)
	must(t, err)
	must(t, bob.Unlock([]byte(pass)))
	return admin, bob, m.ID
}

func TestSyncBothWaysAndPresence(t *testing.T) {
	admin, bob, bobID := team(t)
	na, nb := start(t, admin), start(t, bob)
	must(t, connect(t, nb, na))

	eventually(t, "presence", func() bool { return na.Presence()[bobID].State == "direct" })

	id, err := admin.Save("", app.Entry{Title: "prod db", Password: "p1"})
	must(t, err)
	na.SyncNow()
	eventually(t, "bob to receive the secret", func() bool {
		e, err := bob.Reveal(id)
		return err == nil && e.Password == "p1"
	})

	bid, err := bob.Save("", app.Entry{Title: "bob's", Password: "b1"})
	must(t, err)
	nb.SyncNow()
	eventually(t, "admin to receive bob's secret", func() bool {
		_, err := admin.Reveal(bid)
		return err == nil
	})

	nb.Close()
	eventually(t, "bob to show offline", func() bool {
		p := na.Presence()[bobID]
		return p.State == "offline" && !p.LastSeen.IsZero()
	})
}

func TestOutsiderCannotConnect(t *testing.T) {
	admin, _, _ := team(t)
	eve := app.New(t.TempDir())
	must(t, eve.Create("eve's", "eve", []byte(pass)))
	na, ne := start(t, admin), start(t, eve)
	if err := connect(t, ne, na); err == nil {
		t.Fatal("a non-member must not be able to connect")
	}
}

func TestRemovalTravelsOverSync(t *testing.T) {
	admin, bob, bobID := team(t)
	na, nb := start(t, admin), start(t, bob)
	must(t, connect(t, nb, na))
	eventually(t, "connected", func() bool { return na.Presence()[bobID].State == "direct" })

	_, err := admin.RemoveMember(bobID)
	must(t, err)
	na.SyncNow()
	eventually(t, "bob to be locked out", func() bool { return !bob.Unlocked() && bob.Status() == app.StatusRemoved })
	_ = nb
}

func TestMemberAddedWhileRunningCanConnect(t *testing.T) {
	admin := app.New(t.TempDir())
	must(t, admin.Create("team", "ada", []byte(pass)))
	// Running before dan exists, with rounds too slow to pick him up.
	na, err := Start(admin, Options{Listen: local.Listen, Interval: time.Hour})
	must(t, err)
	t.Cleanup(na.Close)

	dan := app.New(t.TempDir())
	must(t, dan.Join("dan", []byte(pass)))
	code, _, _ := dan.JoinCode()
	m, err := admin.AddMember(code)
	must(t, err)
	bundle := filepath.Join(t.TempDir(), "b")
	_, err = admin.Export(bundle)
	must(t, err)
	_, err = dan.Import(bundle)
	must(t, err)
	must(t, dan.Unlock([]byte(pass)))

	nd := start(t, dan)
	eventually(t, "admin to accept the new member", func() bool { return connect(t, nd, na) == nil })
	eventually(t, "presence", func() bool { return na.Presence()[m.ID].State == "direct" })
}

func TestLocalChangesArePushedAtOnce(t *testing.T) {
	admin, bob, bobID := team(t)
	slow := Options{Listen: local.Listen, Interval: time.Hour}
	na, err := Start(admin, slow)
	must(t, err)
	t.Cleanup(na.Close)
	nb, err := Start(bob, slow)
	must(t, err)
	t.Cleanup(nb.Close)
	must(t, connect(t, nb, na))
	eventually(t, "connected", func() bool { return na.Presence()[bobID].State == "direct" })

	id, err := admin.Save("", app.Entry{Title: "pushed", Password: "x"})
	must(t, err)
	eventually(t, "bob to receive the change without waiting for a round", func() bool {
		_, err := bob.Reveal(id)
		return err == nil
	})
}
