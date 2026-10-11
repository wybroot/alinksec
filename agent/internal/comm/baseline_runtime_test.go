package comm

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestBaselineChannelDoesNotReuseReconnectHistory(t *testing.T) {
	c := &Client{}
	c.setChannelActive(true)
	first := c.channelObservation().Session
	c.noteChannelActivity(first, true)
	c.noteChannelActivity(first, false)
	if v := c.channelObservation(); v.LastSend.IsZero() || v.LastReceive.IsZero() {
		t.Fatal(v)
	}
	c.setChannelActive(false)
	c.setChannelActive(true)
	c.noteChannelActivity(first, true)
	c.noteChannelActivity(first, false)
	v := c.channelObservation()
	if v.Session == first || !v.LastSend.IsZero() || !v.LastReceive.IsZero() {
		t.Fatal(v)
	}
	c.noteChannelActivity(v.Session, true)
	c.noteChannelActivity(v.Session, false)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if v, err := c.channelObservationContext(ctx); err != nil || v.LastReceive.IsZero() {
		t.Fatal(v, err)
	}
}

func TestBaselineChannelMutexDeadlineAndConcurrentObservation(t *testing.T) {
	c := &Client{}
	c.setChannelActive(true)
	c.reportMu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	_, err := c.channelObservationContext(ctx)
	cancel()
	c.reportMu.Unlock()
	if err == nil {
		t.Fatal("busy report lock ignored observation deadline")
	}
	session := c.channelObservation().Session
	var done sync.WaitGroup
	for i := 0; i < 5; i++ {
		done.Add(1)
		go func() {
			defer done.Done()
			for n := 0; n < 30; n++ {
				c.noteChannelActivity(session, n%2 == 0)
				c.channelObservation()
			}
		}()
	}
	done.Wait()
}
