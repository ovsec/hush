package app

import (
	"fmt"
	"sync"
	"time"
)

// Event is one thing hush did in the background, in plain words.
type Event struct {
	At   time.Time
	Kind string
	Msg  string
}

// Feed records events so every UI can show what is happening.
type Feed struct {
	mu     sync.Mutex
	events []Event
	hook   func(Event)
	subs   map[chan Event]struct{}
}

const feedKeep = 500

func newFeed() *Feed { return &Feed{subs: map[chan Event]struct{}{}} }

// Emit records an event. It never blocks.
func (f *Feed) Emit(kind, format string, args ...any) {
	e := Event{At: time.Now(), Kind: kind, Msg: fmt.Sprintf(format, args...)}
	f.mu.Lock()
	f.events = append(f.events, e)
	if len(f.events) > feedKeep {
		f.events = f.events[len(f.events)-feedKeep:]
	}
	hook := f.hook
	for ch := range f.subs {
		select {
		case ch <- e:
		default:
		}
	}
	f.mu.Unlock()
	if hook != nil {
		hook(e)
	}
}

// Subscribe delivers new events until cancel is called. Slow readers miss
// some, but Recent still has them.
func (f *Feed) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 128)
	f.mu.Lock()
	f.subs[ch] = struct{}{}
	f.mu.Unlock()
	return ch, func() {
		f.mu.Lock()
		delete(f.subs, ch)
		f.mu.Unlock()
	}
}

// Recent returns up to n of the latest events, oldest first.
func (f *Feed) Recent(n int) []Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n > len(f.events) {
		n = len(f.events)
	}
	return append([]Event(nil), f.events[len(f.events)-n:]...)
}

// SetHook calls fn synchronously for every event, e.g. to print them.
func (f *Feed) SetHook(fn func(Event)) {
	f.mu.Lock()
	f.hook = fn
	f.mu.Unlock()
}
