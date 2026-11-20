package model

import (
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// the longest user name or password SOCKS5 carries: one byte of length each (RFC 1929)
const mixedProxyLoginMax = 255

// MixedProxyLogin is the login of the rule's mixed proxy: both empty for none. Each part is
// 1 to 255 printable ASCII characters (0x21 to 0x7E, what every app can type and SOCKS5 can
// carry), and the user name has no colon, which HTTP's Basic authentication cannot send in
// it. A login with only one of the two, or one the protocols cannot carry, is an error that
// names the part and what is wrong with it, never its value.
func (s *Section) MixedProxyLogin() (user string, password string, err error) {
	user, password = s.MixedProxyUsername, s.MixedProxyPassword
	switch {
	case user == "" && password == "":
		return "", "", nil
	case password == "":
		return "", "", E.New("the mixed proxy has a user name and no password")
	case user == "":
		return "", "", E.New("the mixed proxy has a password and no user name")
	}
	for _, part := range []struct{ name, value string }{{"user name", user}, {"password", password}} {
		if len(part.value) > mixedProxyLoginMax {
			return "", "", E.New("the ", part.name, " of the mixed proxy is longer than 255 bytes")
		}
		for index := 0; index < len(part.value); index++ {
			if part.value[index] < 0x21 || part.value[index] > 0x7e {
				return "", "", E.New("the ", part.name, " of the mixed proxy has a space, a control character or a letter outside ASCII")
			}
		}
	}
	if strings.Contains(user, ":") {
		return "", "", E.New("the user name of the mixed proxy has a colon, which HTTP cannot send")
	}
	return user, password, nil
}
