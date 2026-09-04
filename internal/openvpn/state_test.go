package openvpn

import "testing"

func TestLifecycleStateMachine(t *testing.T) {
	t.Parallel()
	s := Snapshot{Status: Disconnected}
	for _, next := range []Status{Connecting, Connected, Disconnecting, Disconnected} {
		if err := transition(&s, next); err != nil {
			t.Fatalf("transition to %s: %v", next, err)
		}
	}
	if err := transition(&s, Connected); err == nil {
		t.Fatal("disconnected -> connected should be rejected")
	}
	s = Snapshot{Status: Failed}
	if err := transition(&s, Connecting); err != nil {
		t.Fatalf("failed -> connecting: %v", err)
	}
}
