package openvpn

import (
	"regexp"
	"strings"
)

type LogEvent struct {
	Connected bool
	Interface string
	IP        string
	Failure   string
}

var (
	interfacePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)TUN/TAP device ([[:alnum:]_.:-]+) opened`),
		regexp.MustCompile(`(?i)net_iface_up: set ([[:alnum:]_.:-]+) up`),
	}
	ipPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)net_addr_v4_add: ([0-9.]+)(?:/[0-9]+)? dev`),
		regexp.MustCompile(`(?i)ifconfig ([0-9.]+) `),
		regexp.MustCompile(`(?i)ifconfig_pool_remote_ip=[^,]*,ifconfig_pool_local_ip=([0-9.]+)`),
	}
)

func ParseLogLine(line string) LogEvent {
	event := LogEvent{}
	if strings.Contains(line, "Initialization Sequence Completed") {
		event.Connected = true
	}
	for _, pattern := range interfacePatterns {
		if match := pattern.FindStringSubmatch(line); len(match) == 2 {
			event.Interface = match[1]
			break
		}
	}
	for _, pattern := range ipPatterns {
		if match := pattern.FindStringSubmatch(line); len(match) == 2 {
			event.IP = match[1]
			break
		}
	}
	lower := strings.ToLower(line)
	for _, marker := range []string{"options error:", "error:", "cannot open", "permission denied", "auth_failed", "private key password verification failed", "exiting due to fatal error", "certificate has expired", "no such file or directory"} {
		if strings.Contains(lower, marker) {
			event.Failure = strings.TrimSpace(line)
			break
		}
	}
	return event
}
