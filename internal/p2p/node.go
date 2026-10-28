// Package p2p syncs a vault's signed log directly between members, with no
// server. A member's libp2p peer ID is their Ed25519 vault key, so "is this
// peer a member?" and "who is this peer?" are the same question.
//
// Peers find each other on the LAN with mDNS and, when internet discovery is
// on, through the public libp2p DHT under a rendezvous key only members can
// derive. NAT hole punching and member-run relays cover the rest.
package p2p

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/ovsec/hush/internal/app"
)

// Options choose how a node finds peers.
type Options struct {
	LAN      bool          // mDNS on the local network
	WAN      bool          // public DHT rendezvous, NAT traversal, member relays
	Listen   []string      // multiaddrs; default every interface, any port
	Interval time.Duration // how often to sync and redial; default 30s
}

// Node is a running sync peer for one unlocked vault.
type Node struct {
	svc   *app.Service
	opts  Options
	host  host.Host
	dht   *dht.IpfsDHT
	mdns  mdns.Service
	book  *book
	vault string
	me    string

	ctx    context.Context
	cancel context.CancelFunc
	kick   chan struct{}
	wg     sync.WaitGroup

	mu      sync.Mutex
	members map[string]string // member ID → name; cached so Presence never calls svc
	syncing map[peer.ID]bool
	found   map[peer.ID]bool
	up      map[peer.ID]bool // members we have announced as online
	closed  bool
}

// Start brings up a node for svc, which must be unlocked.
func Start(svc *app.Service, opts Options) (*Node, error) {
	if opts.Interval == 0 {
		opts.Interval = 30 * time.Second
	}
	if len(opts.Listen) == 0 {
		opts.Listen = []string{"/ip4/0.0.0.0/udp/0/quic-v1", "/ip4/0.0.0.0/tcp/0", "/ip6/::/udp/0/quic-v1", "/ip6/::/tcp/0"}
	}
	vaultID, me, _, err := svc.SyncState()
	if err != nil {
		return nil, err
	}
	priv, err := svc.NetKey()
	if err != nil {
		return nil, err
	}
	key, err := crypto.UnmarshalEd25519PrivateKey(priv)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	n := &Node{
		svc: svc, opts: opts, vault: vaultID, me: me, ctx: ctx, cancel: cancel,
		kick: make(chan struct{}, 1), syncing: map[peer.ID]bool{}, found: map[peer.ID]bool{}, up: map[peer.ID]bool{},
		book: loadBook(filepath.Join(svc.Dir(), "peers.json")),
	}
	n.refreshMembers()

	hopts := []libp2p.Option{libp2p.Identity(key), libp2p.ListenAddrStrings(opts.Listen...)}
	if opts.WAN {
		// The DHT and relays need to talk to non-members, so membership is
		// enforced per stream instead of per connection.
		hopts = append(hopts,
			libp2p.NATPortMap(),
			libp2p.EnableHolePunching(),
			libp2p.EnableNATService(),
			libp2p.EnableRelayService(),
			libp2p.EnableAutoRelayWithPeerSource(n.relayCandidates),
		)
	} else {
		hopts = append(hopts, libp2p.ConnectionGater(gater{n}))
	}
	if n.host, err = libp2p.New(hopts...); err != nil {
		cancel()
		return nil, err
	}
	n.host.SetStreamHandler(protocolID, n.handle)
	n.host.Network().Notify(&network.NotifyBundle{ConnectedF: n.connected, DisconnectedF: n.disconnected})
	for id := range n.members {
		if p, err := peerOf(id); err == nil && id != me {
			n.host.Peerstore().AddAddrs(p, n.book.addrs(id), peerstore.RecentlyConnectedAddrTTL)
		}
	}

	modes := []string{}
	if opts.LAN {
		n.mdns = mdns.NewMdnsService(n.host, "hush-"+rendezvous(vaultID)[:12], lanFinder{n})
		if err := n.mdns.Start(); err != nil {
			n.Close()
			return nil, fmt.Errorf("mdns: %w", err)
		}
		modes = append(modes, "LAN (mDNS)")
	}
	if opts.WAN {
		if err := n.startDHT(); err != nil {
			n.Close()
			return nil, err
		}
		modes = append(modes, "internet (DHT rendezvous, hole punching, relays)")
	}
	if len(modes) == 0 {
		modes = append(modes, "known addresses only")
	}
	svc.Feed().Emit("net", "peer %s · listening on %d address(es) · discovery: %s",
		short(n.host.ID()), len(n.host.Addrs()), strings.Join(modes, ", "))

	n.wg.Add(2)
	go n.loop()
	go n.watch()
	return n, nil
}

// watch reacts to the vault changing: local changes are pushed to peers at
// once, and the member list is refreshed as soon as membership may have
// changed, so newcomers are not refused until the next round.
func (n *Node) watch() {
	defer n.wg.Done()
	events, cancel := n.svc.Feed().Subscribe()
	defer cancel()
	for {
		select {
		case <-n.ctx.Done():
			return
		case e := <-events:
			switch e.Kind {
			case "member", "merge":
				n.refreshMembers()
				n.SyncNow()
			case "sign": // a local change: push it now
				n.SyncNow()
			}
		}
	}
}

// Close stops the node and saves what it learned about peers.
func (n *Node) Close() {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return
	}
	n.closed = true
	n.mu.Unlock()
	n.cancel()
	if n.mdns != nil {
		n.mdns.Close()
	}
	if n.dht != nil {
		n.dht.Close()
	}
	if n.host != nil {
		n.host.Close()
	}
	n.wg.Wait()
	n.book.save()
	n.svc.Feed().Emit("net", "sync stopped · disconnected from all peers")
}

// SyncNow asks the node to sync with everyone it can reach.
func (n *Node) SyncNow() {
	select {
	case n.kick <- struct{}{}:
	default:
	}
}

// Addrs are the node's listen addresses with its peer ID.
func (n *Node) Addrs() []string {
	var out []string
	for _, a := range n.host.Addrs() {
		out = append(out, a.String()+"/p2p/"+n.host.ID().String())
	}
	return out
}

// Presence reports each other member's state. Safe to call from the Service.
func (n *Node) Presence() map[string]app.Presence {
	n.mu.Lock()
	ids := make([]string, 0, len(n.members))
	for id := range n.members {
		ids = append(ids, id)
	}
	n.mu.Unlock()
	out := map[string]app.Presence{}
	for _, id := range ids {
		if id == n.me {
			continue
		}
		p, err := peerOf(id)
		if err != nil {
			continue
		}
		if state := n.linkState(p); state != "" {
			out[id] = app.Presence{State: state, LastSeen: time.Now()}
		} else {
			out[id] = app.Presence{State: "offline", LastSeen: n.book.lastSeen(id)}
		}
	}
	return out
}

// linkState is "direct", "relay" or "" if not connected.
func (n *Node) linkState(p peer.ID) string {
	conns := n.host.Network().ConnsToPeer(p)
	if len(conns) == 0 {
		return ""
	}
	for _, c := range conns {
		if !c.Stat().Limited && !isRelayed(c.RemoteMultiaddr()) {
			return "direct"
		}
	}
	return "relay"
}

func (n *Node) loop() {
	defer n.wg.Done()
	t := time.NewTicker(n.opts.Interval)
	defer t.Stop()
	for {
		n.round()
		select {
		case <-n.ctx.Done():
			return
		case <-t.C:
		case <-n.kick:
		}
	}
}

// round syncs with connected members and redials the others.
func (n *Node) round() {
	n.refreshMembers()
	n.mu.Lock()
	ids := make([]string, 0, len(n.members))
	for id := range n.members {
		ids = append(ids, id)
	}
	n.mu.Unlock()
	for _, id := range ids {
		if id == n.me {
			continue
		}
		p, err := peerOf(id)
		if err != nil {
			continue
		}
		if n.linkState(p) != "" {
			n.book.seen(id, time.Now())
			n.goSync(p)
		} else {
			n.goDial(id, p)
		}
	}
	n.book.save()
}

func (n *Node) goDial(id string, p peer.ID) {
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		ctx, cancel := context.WithTimeout(n.ctx, 15*time.Second)
		defer cancel()
		info := peer.AddrInfo{ID: p, Addrs: n.host.Peerstore().Addrs(p)}
		if len(info.Addrs) == 0 && n.dht != nil {
			found, err := n.dht.FindPeer(ctx, p)
			if err != nil {
				return
			}
			info = found
		}
		if len(info.Addrs) > 0 {
			n.host.Connect(ctx, info) // success shows up in connected()
		}
	}()
}

func (n *Node) refreshMembers() {
	m := map[string]string{}
	for _, id := range n.svc.MemberIDs() {
		name, _ := n.svc.Member(id)
		m[id] = name
	}
	n.mu.Lock()
	if len(m) > 0 {
		n.members = m
	}
	n.mu.Unlock()
}

// member reports whether p is a current member, and their name.
func (n *Node) member(p peer.ID) (id, name string, ok bool) {
	id, err := memberOf(p)
	if err != nil {
		return "", "", false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	name, ok = n.members[id]
	return id, name, ok && id != n.me
}

func (n *Node) connected(_ network.Network, c network.Conn) {
	p := c.RemotePeer()
	id, name, ok := n.member(p)
	if !ok || !n.flip(p, true) {
		return
	}
	how := "direct"
	if c.Stat().Limited || isRelayed(c.RemoteMultiaddr()) {
		how = "via relay"
	}
	n.book.seen(id, time.Now())
	n.svc.Feed().Emit("online", "%s connected · %s · %s", name, how, transport(c.RemoteMultiaddr()))
	// Both ends see the connection; the lower peer ID starts the first sync.
	if n.host.ID() < p {
		n.goSync(p)
	}
}

func (n *Node) disconnected(_ network.Network, c network.Conn) {
	p := c.RemotePeer()
	id, name, ok := n.member(p)
	if !ok || len(n.host.Network().ConnsToPeer(p)) > 0 || !n.flip(p, false) {
		return
	}
	n.book.seen(id, time.Now())
	if n.ctx.Err() == nil {
		n.svc.Feed().Emit("offline", "%s went offline", name)
	}
}

// flip records p as up or down and reports whether that changed anything,
// so parallel connections (quic and tcp) announce once.
func (n *Node) flip(p peer.ID, up bool) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.up[p] == up {
		return false
	}
	n.up[p] = up
	return true
}

// relayCandidates offers connected members as relays for AutoRelay.
func (n *Node) relayCandidates(ctx context.Context, num int) <-chan peer.AddrInfo {
	ch := make(chan peer.AddrInfo, num)
	go func() {
		defer close(ch)
		for _, p := range n.host.Network().Peers() {
			if _, _, ok := n.member(p); !ok {
				continue
			}
			select {
			case ch <- n.host.Peerstore().PeerInfo(p):
			case <-ctx.Done():
				return
			}
			if num--; num == 0 {
				return
			}
		}
	}()
	return ch
}

func (n *Node) startDHT() error {
	var err error
	n.dht, err = dht.New(n.host, dht.Mode(dht.ModeAuto), dht.BootstrapPeers(dht.GetDefaultBootstrapPeerAddrInfos()...))
	if err != nil {
		return err
	}
	if err := n.dht.Bootstrap(n.ctx); err != nil {
		return err
	}
	rd := drouting.NewRoutingDiscovery(n.dht)
	ns := "hush/v1/" + rendezvous(n.vault)
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		for _, b := range dht.GetDefaultBootstrapPeerAddrInfos() {
			ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
			n.host.Connect(ctx, b)
			cancel()
		}
		dutil.Advertise(n.ctx, rd, ns)
		for {
			if peers, err := rd.FindPeers(n.ctx, ns); err == nil {
				for info := range peers {
					if _, name, ok := n.member(info.ID); ok && n.linkState(info.ID) == "" && len(info.Addrs) > 0 {
						n.svc.Feed().Emit("found", "%s found through the DHT rendezvous", name)
						n.host.Peerstore().AddAddrs(info.ID, info.Addrs, peerstore.TempAddrTTL)
						go n.host.Connect(n.ctx, info)
					}
				}
			}
			select {
			case <-n.ctx.Done():
				return
			case <-time.After(time.Minute):
			}
		}
	}()
	return nil
}

// lanFinder handles mDNS discoveries.
type lanFinder struct{ n *Node }

func (l lanFinder) HandlePeerFound(info peer.AddrInfo) {
	n := l.n
	_, name, ok := n.member(info.ID)
	if !ok {
		return
	}
	n.mu.Lock()
	first := !n.found[info.ID]
	n.found[info.ID] = true
	n.mu.Unlock()
	if first {
		n.svc.Feed().Emit("found", "%s found on the local network (mDNS)", name)
	}
	if n.linkState(info.ID) == "" {
		ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
		defer cancel()
		n.host.Connect(ctx, info)
	}
}

// gater admits only vault members when internet discovery is off.
type gater struct{ n *Node }

func (g gater) InterceptPeerDial(p peer.ID) bool                                { _, _, ok := g.n.member(p); return ok }
func (g gater) InterceptAddrDial(peer.ID, ma.Multiaddr) bool                    { return true }
func (g gater) InterceptAccept(network.ConnMultiaddrs) bool                     { return true }
func (g gater) InterceptUpgraded(network.Conn) (bool, control.DisconnectReason) { return true, 0 }
func (g gater) InterceptSecured(_ network.Direction, p peer.ID, _ network.ConnMultiaddrs) bool {
	_, _, ok := g.n.member(p)
	return ok
}

// ── helpers ─────────────────────────────────────────────────────────

func peerOf(memberID string) (peer.ID, error) {
	b, err := hex.DecodeString(memberID)
	if err != nil {
		return "", err
	}
	pub, err := crypto.UnmarshalEd25519PublicKey(b)
	if err != nil {
		return "", err
	}
	return peer.IDFromPublicKey(pub)
}

func memberOf(p peer.ID) (string, error) {
	pub, err := p.ExtractPublicKey()
	if err != nil {
		return "", err
	}
	if _, ok := pub.(*crypto.Ed25519PublicKey); !ok {
		return "", fmt.Errorf("not an ed25519 peer")
	}
	raw, err := pub.Raw()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// rendezvous derives a name only members can compute from the vault ID.
func rendezvous(vaultID string) string {
	sum := sha256.Sum256([]byte("hush/rendezvous/v1|" + vaultID))
	return hex.EncodeToString(sum[:16])
}

func isRelayed(a ma.Multiaddr) bool {
	_, err := a.ValueForProtocol(ma.P_CIRCUIT)
	return err == nil
}

func transport(a ma.Multiaddr) string {
	s := a.String()
	switch {
	case strings.Contains(s, "/quic"):
		return "quic"
	case strings.Contains(s, "/tcp"):
		return "tcp"
	}
	return s
}

func short(p peer.ID) string {
	s := p.String()
	if len(s) > 10 {
		return s[:4] + "…" + s[len(s)-4:]
	}
	return s
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
