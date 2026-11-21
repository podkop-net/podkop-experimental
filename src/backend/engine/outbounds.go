package engine

import (
	"context"
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
)

// The servers of a configuration of sing-box a provider sends (sing-box JSON) are links too, every
// option by its path (subscription/singbox.go); before that, this sing-box reads the options of the
// outbound and writes them again, as the decoder of the links makes an outbound.

// outboundOptions are the options of the types of outbounds a link makes, as this sing-box
// declares them, whatever the build has (the decoder's list, common/sharelink fallback.go): an
// outbound the build does not have is refused when it is built, as its link is.
func outboundOptions(kind string) any {
	switch kind {
	case "vless":
		return new(option.VLESSOutboundOptions)
	case "vmess":
		return new(option.VMessOutboundOptions)
	case "trojan":
		return new(option.TrojanOutboundOptions)
	case "shadowsocks":
		return new(option.ShadowsocksOutboundOptions)
	case "socks":
		return new(option.SOCKSOutboundOptions)
	case "http":
		return new(option.HTTPOutboundOptions)
	case "hysteria":
		return new(option.HysteriaOutboundOptions)
	case "hysteria2":
		return new(option.Hysteria2OutboundOptions)
	case "tuic":
		return new(option.TUICOutboundOptions)
	case "anytls":
		return new(option.AnyTLSOutboundOptions)
	case "naive":
		return new(option.NaiveOutboundOptions)
	}
	return nil
}

// NormalizeOutbound has this sing-box read the options of an outbound of a type (an object without
// the type and the tag) and write them again as it writes them: no option at its default, a list
// of one as the one value. An option this sing-box does not have for the type is refused, named
// when it is a plain name; the error holds no value.
func NormalizeOutbound(kind string, options []byte) ([]byte, error) {
	target := outboundOptions(kind)
	if target == nil {
		return nil, E.New("no link makes an outbound of this type")
	}
	err := json.UnmarshalContextDisallowUnknownFields(context.Background(), options, target)
	if err != nil {
		return nil, E.New(optionsError(err))
	}
	content, err := json.Marshal(target)
	if err != nil {
		return nil, E.New("this sing-box cannot write the outbound")
	}
	return content, nil
}

// optionsError is why sing-box does not read the options of an outbound, without their values:
// the option it does not have, or cannot read, when it is a plain name.
func optionsError(err error) string {
	message := err.Error()
	if at := strings.Index(message, "unknown field "); at >= 0 {
		name := strings.Trim(message[at+len("unknown field "):], `"' `)
		if plainOption(name) {
			return "this sing-box has no option " + name + " for the outbound (the syntax of another version, or of another type)"
		}
		return "this sing-box has no option of the outbound (the syntax of another version, or of another type)"
	}
	const marker = "Go struct field "
	if at := strings.Index(message, marker); at >= 0 {
		field := message[at+len(marker):]
		if space := strings.IndexByte(field, ' '); space >= 0 {
			field = field[:space]
		}
		if dot := strings.LastIndexByte(field, '.'); dot >= 0 {
			field = field[dot+1:]
		}
		if plainOption(field) {
			return "the option " + field + " of the outbound has a value of the wrong type"
		}
	}
	return "this sing-box cannot read the outbound"
}

// plainOption tells a name of an option a message may name: letters, digits and "_", as the
// options have.
func plainOption(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for index := 0; index < len(name); index++ {
		switch char := name[index]; {
		case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z', char >= '0' && char <= '9', char == '_':
		default:
			return false
		}
	}
	return true
}
