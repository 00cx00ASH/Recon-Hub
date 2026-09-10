// Package bus is an in-memory fan-out of job events to live SSE subscribers.
package bus

import (
	"sync"

	"reconhub/internal/store"
)

// Bus fans job events out to any number of per-job subscribers.
type Bus struct {
	mu   sync.Mutex
	subs map[string]map[chan store.Event]struct{}
}

// New returns an empty Bus.
func New() *Bus {
	return &Bus{subs: map[string]map[chan store.Event]struct{}{}}
}

// Subscribe returns a buffered channel of events for jobID and a cancel func
// that unsubscribes and closes the channel. Cancel is safe to call more than once.
func (b *Bus) Subscribe(jobID string) (<-chan store.Event, func()) {
	ch := make(chan store.Event, 256)

	b.mu.Lock()
	m := b.subs[jobID]
	if m == nil {
		m = map[chan store.Event]struct{}{}
		b.subs[jobID] = m
	}
	m[ch] = struct{}{}
	b.mu.Unlock()

	var once sync.Once
	cancel := func() {
		once.Do(func() {
			b.mu.Lock()
			if m := b.subs[jobID]; m != nil {
				delete(m, ch)
				if len(m) == 0 {
					delete(b.subs, jobID)
				}
			}
			b.mu.Unlock()
			close(ch)
		})
	}
	return ch, cancel
}

// Publish delivers e to every current subscriber of jobID. A subscriber whose
// buffer is full is skipped rather than blocking the publisher.
func (b *Bus) Publish(jobID string, e store.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs[jobID] {
		select {
		case ch <- e:
		default:
		}
	}
}
