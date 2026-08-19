package store

import (
	"testing"
	"time"

	"netwatch/internal/model"
)

// TestPublishSubscribe exercises the mechanism cmd/netwatch's
// forwardStoreEvents relies on to relay events into the Wails frontend:
// Add* -> ring buffer -> Subscribe channel. This used to be covered
// end-to-end through a WebSocket in internal/web; now that the transport
// is Wails events instead of a socket, the transport-agnostic part (the
// store itself) is what's tested directly.
func TestPublishSubscribe(t *testing.T) {
	dir := t.TempDir()
	st, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer st.Close()

	ch := st.Subscribe()
	defer st.Unsubscribe(ch)

	alert := model.Alert{
		Seq: 1, Time: time.Now(), Severity: model.SevCritical,
		Rule: "file_then_network_exfil", Title: "test", Detail: "detail",
		PID: 1234, ProcName: "evil.exe",
	}
	st.AddAlert(alert)

	select {
	case env := <-ch:
		if env.Type != "alert" {
			t.Fatalf("expected type=alert, got %q", env.Type)
		}
		got, ok := env.Data.(model.Alert)
		if !ok {
			t.Fatalf("expected model.Alert payload, got %T", env.Data)
		}
		if got.ProcName != "evil.exe" || got.Severity != model.SevCritical {
			t.Fatalf("unexpected payload: %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for published event")
	}

	// snapshot + ack round trip
	if got := st.RecentAlerts(10); len(got) != 1 {
		t.Fatalf("expected 1 alert in snapshot, got %d", len(got))
	}
	st.AckAlert(1)
	if got := st.RecentAlerts(10); len(got) != 1 || !got[0].Ack {
		t.Fatalf("expected alert to be acknowledged, got %+v", got)
	}
}

// A slow/absent subscriber must never block the publisher — the collector
// pipeline (ETW dispatch loop) publishes synchronously and cannot afford
// to stall on a full channel.
func TestPublishDoesNotBlockOnSlowSubscriber(t *testing.T) {
	dir := t.TempDir()
	st, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer st.Close()

	ch := st.Subscribe()
	defer st.Unsubscribe(ch)
	// Deliberately never drain ch.

	done := make(chan struct{})
	go func() {
		for i := 0; i < 500; i++ {
			st.AddNet(model.NetEvent{Seq: uint64(i), Time: time.Now(), PID: 1, Direction: "connect"})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("AddNet blocked on a slow subscriber instead of dropping")
	}
}
