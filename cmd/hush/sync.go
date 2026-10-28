package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/ovsec/hush/internal/app"
	"github.com/ovsec/hush/internal/p2p"
)

// syncFlag registers -sync on fs; the default comes from HUSH_SYNC.
func syncFlag(fs *flag.FlagSet) *string {
	def := os.Getenv("HUSH_SYNC")
	if def == "" {
		def = "internet"
	}
	return fs.String("sync", def, "peer-to-peer sync: internet (LAN + DHT + relays), lan, or off")
}

// syncer runs a p2p node whenever the vault is unlocked.
type syncer struct {
	svc  *app.Service
	opts p2p.Options

	mu      sync.Mutex
	node    *p2p.Node
	stopped bool
}

// startSync keeps a node running while svc is unlocked. stop shuts it down.
func startSync(svc *app.Service, mode string) (stop func(), err error) {
	opts := p2p.Options{}
	switch mode {
	case "off":
		return func() {}, nil
	case "lan":
		opts.LAN = true
	case "internet":
		opts.LAN, opts.WAN = true, true
	default:
		return nil, fmt.Errorf("-sync must be internet, lan or off, not %q", mode)
	}
	s := &syncer{svc: svc, opts: opts}
	svc.OnChange(s.reconcile)
	s.reconcile()
	return func() {
		svc.OnChange(nil)
		s.mu.Lock()
		defer s.mu.Unlock()
		s.stopped = true
		s.stopNode()
	}, nil
}

func (s *syncer) reconcile() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return
	}
	switch unlocked := s.svc.Unlocked(); {
	case unlocked && s.node == nil:
		n, err := p2p.Start(s.svc, s.opts)
		if err != nil {
			s.svc.Feed().Emit("deny", "sync could not start: %v", err)
			return
		}
		s.node = n
		s.svc.SetPresence(n.Presence)
	case !unlocked && s.node != nil:
		s.stopNode()
	}
}

func (s *syncer) stopNode() {
	if s.node == nil {
		return
	}
	s.svc.SetPresence(nil)
	s.node.Close()
	s.node = nil
}

// cmdDaemon keeps the vault unlocked and syncing: an always-on peer.
func cmdDaemon(svc *app.Service, args []string) error {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	mode := syncFlag(fs)
	quiet := fs.Bool("q", false, "do not print activity")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if *mode == "off" {
		return fmt.Errorf("a daemon without sync does nothing; use -sync lan or internet")
	}
	narrate(svc, !*quiet)
	if err := unlock(svc); err != nil {
		return err
	}
	stop, err := startSync(svc, *mode)
	if err != nil {
		return err
	}
	defer stop()
	defer svc.Lock()
	fmt.Fprintln(os.Stderr, "hush daemon is syncing. Press Ctrl+C to stop; keys are wiped when it does.")
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	<-ctx.Done()
	return nil
}
