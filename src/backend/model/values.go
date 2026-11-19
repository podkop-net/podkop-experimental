package model

import (
	"net/netip"
	"strings"
)

// IsIPv4 tells whether the text is an IPv4 address in dotted form, octets without leading
// zeros: what the shell backend takes for one.
func IsIPv4(text string) bool {
	parts := strings.Split(text, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if !isOctet(part) {
			return false
		}
	}
	return true
}

// IsIPv4CIDR tells whether the text is an IPv4 address with a prefix length of 0 to 32.
func IsIPv4CIDR(text string) bool {
	address, prefix, found := strings.Cut(text, "/")
	if !found || !IsIPv4(address) {
		return false
	}
	switch len(prefix) {
	case 1:
		return prefix[0] >= '0' && prefix[0] <= '9'
	case 2:
		return (prefix[0] == '1' || prefix[0] == '2') && prefix[1] >= '0' && prefix[1] <= '9' ||
			prefix[0] == '3' && prefix[1] >= '0' && prefix[1] <= '2'
	}
	return false
}

// IsIPv6 tells whether the text is an IPv6 address as netip reads one, without a zone and
// not an IPv4 address in IPv6 form (::ffff:a.b.c.d).
func IsIPv6(text string) bool {
	if !strings.Contains(text, ":") {
		return false
	}
	address, err := netip.ParseAddr(text)
	return err == nil && address.Is6() && !address.Is4In6() && address.Zone() == ""
}

// IsIPv6CIDR tells whether the text is an IPv6 address with a prefix length of 0 to 128.
func IsIPv6CIDR(text string) bool {
	address, _, found := strings.Cut(text, "/")
	if !found || !IsIPv6(address) {
		return false
	}
	_, err := netip.ParsePrefix(text)
	return err == nil
}

// IsIP tells whether the text is an IPv4 address (IsIPv4) or an IPv6 one (IsIPv6).
func IsIP(text string) bool {
	return IsIPv4(text) || IsIPv6(text)
}

// IsCIDR tells whether the text is an IPv4 or an IPv6 address with a prefix length.
func IsCIDR(text string) bool {
	return IsIPv4CIDR(text) || IsIPv6CIDR(text)
}

func isOctet(part string) bool {
	if len(part) == 0 || len(part) > 3 {
		return false
	}
	value := 0
	for _, character := range []byte(part) {
		if character < '0' || character > '9' {
			return false
		}
		value = value*10 + int(character-'0')
	}
	if len(part) > 1 && part[0] == '0' {
		return false
	}
	return value <= 255
}

// IsDomainSuffix tells whether the text is a domain name in lower case, with or without a
// leading dot: labels of letters, digits and hyphens that neither begin nor end with a
// hyphen.
func IsDomainSuffix(text string) bool {
	text = strings.TrimPrefix(text, ".")
	if text == "" {
		return false
	}
	for _, label := range strings.Split(text, ".") {
		if label == "" || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range []byte(label) {
			if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-') {
				return false
			}
		}
	}
	return true
}
