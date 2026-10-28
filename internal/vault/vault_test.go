package vault

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ovsec/hush/internal/crypt"
	"github.com/ovsec/hush/internal/oplog"
)

type fixture struct {
	t     *testing.T
	st    *State
	admin *crypt.Identity
}

func newFixture(t *testing.T) *fixture {
	admin, _ := crypt.NewIdentity()
	f := &fixture{t: t, st: New(), admin: admin}
	f.must(f.op(admin, KindGenesis, Genesis{VaultID: "v1", Name: "team", Admin: Member{ID: admin.ID(), Box: admin.BoxID(), Name: "ada"}}))
	f.must(f.op(admin, KindKeyEpoch, KeyEpoch{Epoch: 1, Wrapped: map[string][]byte{admin.ID(): []byte("x")}}))
	return f
}

func (f *fixture) build(by *crypt.Identity, kind string, body any, clock uint64) *oplog.Op {
	b, _ := json.Marshal(body)
	op := &oplog.Op{V: 1, Parents: f.st.Heads(), Author: by.ID(), Clock: clock, Kind: kind, Body: b}
	if err := op.Sign(by); err != nil {
		f.t.Fatal(err)
	}
	return op
}

func (f *fixture) op(by *crypt.Identity, kind string, body any) error {
	return f.st.Apply(f.build(by, kind, body, f.st.Clock+1))
}

func (f *fixture) must(err error) {
	f.t.Helper()
	if err != nil {
		f.t.Fatal(err)
	}
}

func TestGenesisRequired(t *testing.T) {
	id, _ := crypt.NewIdentity()
	f := &fixture{t: t, st: New()}
	if err := f.op(id, KindPut, SecretPut{Entry: "e", Epoch: 1}); err == nil {
		t.Fatal("log without genesis must be rejected")
	}
}

func TestOutsiderRejected(t *testing.T) {
	f := newFixture(t)
	eve, _ := crypt.NewIdentity()
	if err := f.op(eve, KindPut, SecretPut{Entry: "e", Epoch: 1}); err == nil || !strings.Contains(err.Error(), "not a member") {
		t.Fatalf("outsider write: %v", err)
	}
	if err := f.op(eve, KindKeyEpoch, KeyEpoch{Epoch: 2}); err == nil {
		t.Fatal("outsider key rotation must be rejected")
	}
}

func TestTamperedOpRejected(t *testing.T) {
	f := newFixture(t)
	op := f.build(f.admin, KindPut, SecretPut{Entry: "e", Epoch: 1, CT: []byte("aaaa")}, 9)
	op.Body = json.RawMessage(strings.Replace(string(op.Body), "YWFhYQ==", "YmJiYg==", 1))
	if err := f.st.Apply(op); err == nil {
		t.Fatal("tampered body must be rejected")
	}
}

func TestUnknownEpochAndParent(t *testing.T) {
	f := newFixture(t)
	if err := f.op(f.admin, KindPut, SecretPut{Entry: "e", Epoch: 7}); err == nil {
		t.Fatal("unknown epoch must be rejected")
	}
	op := f.build(f.admin, KindPut, SecretPut{Entry: "e", Epoch: 1}, 9)
	op.Parents = []string{"deadbeef"}
	_ = op.Sign(f.admin)
	if err := f.st.Apply(op); err == nil {
		t.Fatal("unknown parent must be rejected")
	}
}

func TestLastWriterWinsIsOrderIndependent(t *testing.T) {
	f := newFixture(t)
	older := f.build(f.admin, KindPut, SecretPut{Entry: "e", Epoch: 1, CT: []byte("old")}, 5)
	newer := f.build(f.admin, KindPut, SecretPut{Entry: "e", Epoch: 1, CT: []byte("new")}, 6)
	f.must(f.st.Apply(newer))
	f.must(f.st.Apply(older))
	rec := f.st.Records["e"]
	if string(rec.CT) != "new" || rec.Version != 2 {
		t.Fatalf("got %q v%d", rec.CT, rec.Version)
	}
	f.must(f.st.Apply(newer)) // idempotent
	if f.st.Records["e"].Version != 2 {
		t.Fatal("re-applying must be a no-op")
	}
}

func TestMembershipRules(t *testing.T) {
	f := newFixture(t)
	bob, _ := crypt.NewIdentity()
	bobM := Member{ID: bob.ID(), Box: bob.BoxID(), Name: "bob"}
	if err := f.op(bob, KindAdd, AddMember{Member: bobM, Wrapped: map[int][]byte{1: []byte("k")}}); err == nil {
		t.Fatal("non-admin add must be rejected")
	}
	if err := f.op(f.admin, KindAdd, AddMember{Member: bobM}); err == nil {
		t.Fatal("add without epoch keys must be rejected")
	}
	f.must(f.op(f.admin, KindAdd, AddMember{Member: bobM, Wrapped: map[int][]byte{1: []byte("k")}}))
	f.must(f.op(bob, KindPut, SecretPut{Entry: "e", Epoch: 1}))

	if err := f.op(f.admin, KindKeyEpoch, KeyEpoch{Epoch: 2, Wrapped: map[string][]byte{f.admin.ID(): []byte("x")}}); err == nil {
		t.Fatal("a new epoch must be sealed to every member")
	}
	if err := f.op(bob, KindRemove, RemoveMember{ID: f.admin.ID()}); err == nil {
		t.Fatal("members cannot remove")
	}
	f.must(f.op(f.admin, KindRemove, RemoveMember{ID: bob.ID()}))
	if got := f.st.Records["e"].Exposed; len(got) != 1 || got[0] != "bob" {
		t.Fatalf("exposure: %v", got)
	}
	f.must(f.op(bob, KindPut, SecretPut{Entry: "late", Epoch: 1}))
	if _, ok := f.st.Records["late"]; ok || f.st.Ignored() != 1 {
		t.Fatal("a removed member's later writes must have no effect")
	}
	if err := f.op(f.admin, KindAdd, AddMember{Member: bobM, Wrapped: map[int][]byte{1: []byte("k")}}); err == nil {
		t.Fatal("a removed key must not rejoin")
	}
}

func TestMergeOutOfOrder(t *testing.T) {
	src := newFixture(t)
	src.must(src.op(src.admin, KindPut, SecretPut{Entry: "a", Epoch: 1}))
	src.must(src.op(src.admin, KindPut, SecretPut{Entry: "b", Epoch: 1}))
	ops := src.st.Ops()
	reversed := make([]*oplog.Op, 0, len(ops))
	for i := len(ops) - 1; i >= 0; i-- {
		reversed = append(reversed, ops[i])
	}
	dst := New()
	added, rejected := dst.Merge(reversed)
	if len(added) != len(ops) || len(rejected) != 0 || len(dst.Records) != 2 {
		t.Fatalf("added %d rejected %v", len(added), rejected)
	}
}

func TestRemovalAndConcurrentWriteConverge(t *testing.T) {
	f := newFixture(t)
	bob, _ := crypt.NewIdentity()
	f.must(f.op(f.admin, KindAdd, AddMember{Member: Member{ID: bob.ID(), Box: bob.BoxID(), Name: "bob"}, Wrapped: map[int][]byte{1: []byte("k")}}))
	f.must(f.op(bob, KindPut, SecretPut{Entry: "seen", Epoch: 1})) // admin sees this one
	base := f.st.Heads()

	// bob and the admin act at the same time, each unaware of the other.
	b, _ := json.Marshal(SecretPut{Entry: "sneaky", Epoch: 1})
	write := &oplog.Op{V: 1, Parents: base, Author: bob.ID(), Clock: 10, Kind: KindPut, Body: b}
	write.Sign(bob)
	b, _ = json.Marshal(RemoveMember{ID: bob.ID()})
	remove := &oplog.Op{V: 1, Parents: base, Author: f.admin.ID(), Clock: 10, Kind: KindRemove, Body: b}
	remove.Sign(f.admin)

	common := f.st.Ops()
	peerA, _ := Replay(common)
	peerA.Merge([]*oplog.Op{write})
	peerA.Merge([]*oplog.Op{remove})
	if !peerA.Stale {
		t.Fatal("peer that applied the write first must notice it is stale")
	}
	peerA, _ = Replay(peerA.Ops())

	peerB, _ := Replay(common)
	peerB.Merge([]*oplog.Op{remove})
	peerB.Merge([]*oplog.Op{write})

	for name, st := range map[string]*State{"A": peerA, "B": peerB} {
		if _, ok := st.Records["sneaky"]; ok {
			t.Fatalf("peer %s kept a write the admin never saw", name)
		}
		if _, ok := st.Records["seen"]; !ok {
			t.Fatalf("peer %s dropped a write the admin had seen", name)
		}
		if st.Ignored() != 1 || len(st.Ops()) != len(common)+2 {
			t.Fatalf("peer %s: ignored %d, ops %d", name, st.Ignored(), len(st.Ops()))
		}
	}
}
