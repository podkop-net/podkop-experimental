package engine

import (
	"regexp"
	"strings"
)

// The logins of the proxy inbounds in sing-box's log. sing's handshakes of SOCKS4, SOCKS5 and
// HTTP put what a client tried into the error of a failed login ("socks5: authentication
// failed, username=…, password=…", "http: authentication failed, Proxy-Authorization=…"),
// which the inbound logs at the level error; the user name of a login that passed starts the
// line of each of its connections ("[user] inbound connection to …", at the level info).
var (
	failedLogin = regexp.MustCompile(`(?s)(authentication failed, (?:username|Proxy-Authorization)=).*`)
	passedLogin = regexp.MustCompile(`(inbound/(?:mixed|socks|http)\[.*?\]: \[).*?(\] inbound (?:packet )?connection)`)
)

// MaskLogin returns a line of sing-box's log with the logins of the proxy inbounds replaced
// by the word MASKED: all a client sent in a failed login, and the user name of one that
// passed. The sink of BuildLogged is given its lines masked; sing-box's own output (the
// system log) is not.
func MaskLogin(message string) string {
	if strings.Contains(message, "authentication failed, ") {
		message = failedLogin.ReplaceAllString(message, "${1}MASKED")
	}
	if strings.Contains(message, "] inbound ") {
		message = passedLogin.ReplaceAllString(message, "${1}MASKED${2}")
	}
	return message
}
