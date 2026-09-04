package openvpn

import "testing"

func TestParseManagementLine(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		line        string
		wantPending bool
		wantURL     string
	}{
		{name: "pending", line: ">STATE:1788541200,AUTH_PENDING,,,,", wantPending: true},
		{name: "webauth", line: ">INFOMSG:WEB_AUTH:external:https://id.example.test/oauth?state=secret", wantPending: true, wantURL: "https://id.example.test/oauth?state=secret"},
		{name: "legacy open url", line: ">INFOMSG:OPEN_URL:https://id.example.test/login", wantPending: true, wantURL: "https://id.example.test/login"},
		{name: "reject http", line: ">INFOMSG:WEB_AUTH:external:http://id.example.test/login"},
		{name: "reject credentials in url", line: ">INFOMSG:WEB_AUTH:external:https://user:pass@id.example.test/login"},
		{name: "unrelated", line: ">LOG:1788541200,N,hello"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := parseManagementLine(test.line)
			if got.authPending != test.wantPending || got.authURL != test.wantURL {
				t.Fatalf("parseManagementLine(%q) = %#v", test.line, got)
			}
		})
	}
}
