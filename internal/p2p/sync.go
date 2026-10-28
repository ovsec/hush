package p2p

import (
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/ovsec/hush/internal/app"
	"github.com/ovsec/hush/internal/oplog"
)

const (
	protocolID = "/hush/sync/1"
	maxStream  = 64 << 20
	streamTTL  = time.Minute
)

// hello opens a sync: which ops I hold, plus gossip about when each member
// was last seen and where they can be reached.
type hello struct {
	V     int                 `json:"v"`
	Vault string              `json:"vault"`
	IDs   []string            `json:"ids"`
	Seen  map[string]int64    `json:"seen"`
	Addrs map[string][]string `json:"addrs"`
}

type batch struct {
	Ops []*oplog.Op `json:"ops"`
}

// The initiator sends hello; the responder answers with its hello and the
// ops the initiator lacks; the initiator merges them and sends back the ops
// the responder lacks. One round trip, no deadlock.

func (n *Node) goSync(p peer.ID) {
	n.mu.Lock()
	if n.syncing[p] {
		n.mu.Unlock()
		return
	}
	n.syncing[p] = true
	n.mu.Unlock()
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		defer func() {
			n.mu.Lock()
			delete(n.syncing, p)
			n.mu.Unlock()
		}()
		if err := n.syncWith(p); err != nil && n.ctx.Err() == nil {
			_, name, _ := n.member(p)
			n.svc.Feed().Emit("deny", "sync with %s failed: %v", name, err)
		}
	}()
}

func (n *Node) syncWith(p peer.ID) error {
	id, name, ok := n.member(p)
	if !ok {
		return errors.New("not a member")
	}
	ctx := network.WithAllowLimitedConn(n.ctx, "hush sync")
	s, err := n.host.NewStream(ctx, p, protocolID)
	if err != nil {
		return err
	}
	defer s.Close()
	s.SetDeadline(time.Now().Add(streamTTL))
	start := time.Now()
	enc, dec := json.NewEncoder(s), json.NewDecoder(io.LimitReader(s, maxStream))

	mine, err := n.hello()
	if err != nil {
		return err
	}
	if err := enc.Encode(mine); err != nil {
		return err
	}
	var theirs hello
	var in batch
	if err := dec.Decode(&theirs); err != nil {
		return err
	}
	if err := dec.Decode(&in); err != nil {
		return err
	}
	if theirs.Vault != n.vault {
		return errors.New("peer is on a different vault")
	}
	out := n.lacking(theirs.IDs)
	if err := enc.Encode(batch{Ops: out}); err != nil {
		return err
	}
	s.CloseWrite()
	return n.absorb(id, name, theirs, in.Ops, len(out), time.Since(start))
}

func (n *Node) handle(s network.Stream) {
	defer s.Close()
	p := s.Conn().RemotePeer()
	id, name, ok := n.member(p)
	if !ok {
		n.svc.Feed().Emit("deny", "refused a sync from %s: not a member of this vault", short(p))
		s.Reset()
		return
	}
	s.SetDeadline(time.Now().Add(streamTTL))
	start := time.Now()
	enc, dec := json.NewEncoder(s), json.NewDecoder(io.LimitReader(s, maxStream))

	var theirs hello
	if err := dec.Decode(&theirs); err != nil || theirs.Vault != n.vault {
		s.Reset()
		return
	}
	mine, err := n.hello()
	if err != nil {
		s.Reset()
		return
	}
	out := n.lacking(theirs.IDs)
	if enc.Encode(mine) != nil || enc.Encode(batch{Ops: out}) != nil {
		return
	}
	var in batch
	if err := dec.Decode(&in); err != nil {
		return
	}
	n.absorb(id, name, theirs, in.Ops, len(out), time.Since(start))
}

func (n *Node) hello() (hello, error) {
	_, _, ids, err := n.svc.SyncState()
	if err != nil {
		return hello{}, err
	}
	h := hello{V: 1, Vault: n.vault, IDs: ids, Seen: map[string]int64{}, Addrs: map[string][]string{}}
	now := time.Now()
	h.Seen[n.me] = now.UnixMilli()
	for _, a := range n.host.Addrs() {
		h.Addrs[n.me] = append(h.Addrs[n.me], a.String())
	}
	n.mu.Lock()
	ids = sortedKeys(n.members)
	n.mu.Unlock()
	for _, id := range ids {
		if id == n.me {
			continue
		}
		if t := n.book.lastSeen(id); !t.IsZero() {
			h.Seen[id] = t.UnixMilli()
		}
		if p, err := peerOf(id); err == nil {
			if n.linkState(p) != "" {
				h.Seen[id] = now.UnixMilli()
			}
			for _, a := range n.host.Peerstore().Addrs(p) {
				h.Addrs[id] = append(h.Addrs[id], a.String())
			}
		}
	}
	return h, nil
}

// lacking returns our ops the peer does not have, in our (causal) order.
func (n *Node) lacking(theirIDs []string) []*oplog.Op {
	have := make(map[string]bool, len(theirIDs))
	for _, id := range theirIDs {
		have[id] = true
	}
	_, _, mine, err := n.svc.SyncState()
	if err != nil {
		return nil
	}
	var want []string
	for _, id := range mine {
		if !have[id] {
			want = append(want, id)
		}
	}
	return n.svc.OpsByID(want)
}

func (n *Node) absorb(id, name string, theirs hello, ops []*oplog.Op, sent int, took time.Duration) error {
	got := 0
	if len(ops) > 0 {
		res, err := n.svc.MergeOps(ops, name)
		got = res.Added
		if errors.Is(err, app.ErrRemoved) {
			go n.Close()
			return nil
		}
		if err != nil {
			return err
		}
	}
	n.book.seen(id, time.Now())
	n.mu.Lock()
	members := n.members
	n.mu.Unlock()
	for mid, ms := range theirs.Seen {
		if _, ok := members[mid]; ok && mid != n.me {
			n.book.seen(mid, time.UnixMilli(ms))
		}
	}
	for mid, addrs := range theirs.Addrs {
		p, err := peerOf(mid)
		if _, ok := members[mid]; !ok || mid == n.me || err != nil {
			continue
		}
		var good []ma.Multiaddr
		for _, a := range addrs {
			if m, err := ma.NewMultiaddr(a); err == nil {
				good = append(good, m)
			}
		}
		n.host.Peerstore().AddAddrs(p, good, peerstore.TempAddrTTL)
		n.book.setAddrs(mid, addrs)
	}
	if got > 0 || sent > 0 {
		n.svc.Feed().Emit("sync", "with %s · ↓ %d op(s) · ↑ %d op(s) · %s", name, got, sent, took.Round(time.Millisecond))
		if got > 0 {
			n.refreshMembers()
		}
	}
	return nil
}
