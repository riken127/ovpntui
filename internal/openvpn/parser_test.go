package openvpn

import "testing"

func TestParseLogLine(t *testing.T) {
	t.Parallel()
	tests := []struct {
		line  string
		check func(LogEvent) bool
	}{
		{"TUN/TAP device tun0 opened", func(e LogEvent) bool { return e.Interface == "tun0" }},
		{"net_iface_up: set ovpn-dco0 up", func(e LogEvent) bool { return e.Interface == "ovpn-dco0" }},
		{"net_addr_v4_add: 10.8.0.2/24 dev tun0", func(e LogEvent) bool { return e.IP == "10.8.0.2" }},
		{"Initialization Sequence Completed", func(e LogEvent) bool { return e.Connected }},
		{"AUTH_FAILED", func(e LogEvent) bool { return e.Failure != "" }},
		{"Options error: missing certificate", func(e LogEvent) bool { return e.Failure != "" }},
	}
	for _, test := range tests {
		event := ParseLogLine(test.line)
		if !test.check(event) {
			t.Errorf("ParseLogLine(%q) = %#v", test.line, event)
		}
	}
}
