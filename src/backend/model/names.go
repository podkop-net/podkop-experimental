package model

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Names are what the rules and the sources are called outside the settings: in the tags of
// their outbounds, and so in the log of sing-box, in YACD, in the Clash API and in global
// check. They are what the page shows, so a label changed on the page reaches all of them
// with the next configuration; the section names stay the keys the rows and the settings
// refer by. A rule is called by its label, otherwise by its section. A source is called by
// its label, otherwise as the page calls it (sourceAutoLabel): the host of a subscription,
// the name after "#" of its one link (or its scheme and host), the tag or type of its
// outbound JSON, its interface. A name an earlier rule (or source) has is told apart by the
// section in parentheses: "Germany (src4)".
type Names struct {
	// Rules are the names of the rules, by section.
	Rules map[string]string
	// Sources are the names of the sources, by section.
	Sources map[string]string
}

// Names returns the names of the rules and the sources.
func (c *Config) Names() Names {
	names := Names{Rules: make(map[string]string, len(c.Sections)), Sources: make(map[string]string, len(c.Sources))}
	taken := make(map[string]bool)
	for index := range c.Sections {
		section := &c.Sections[index]
		names.Rules[section.Name] = uniqueName(oneLine(section.Label), section.Name, taken)
	}
	taken = make(map[string]bool)
	for index := range c.Sources {
		source := &c.Sources[index]
		names.Sources[source.Name] = uniqueName(source.autoName(), source.Name, taken)
	}
	return names
}

// Rule is the name of a rule; the section itself for one the settings do not have.
func (n Names) Rule(section string) string {
	if name := n.Rules[section]; name != "" {
		return name
	}
	return section
}

// Source is the name of a source; the section itself for one the settings do not have.
func (n Names) Source(section string) string {
	if name := n.Sources[section]; name != "" {
		return name
	}
	return section
}

// RuleText names a rule in a message: its name, with its section when that differs, so that
// the settings are found by it too.
func (n Names) RuleText(section string) string {
	return withSection(n.Rule(section), section)
}

// SourceText names a source in a message as RuleText names a rule.
func (n Names) SourceText(section string) string {
	return withSection(n.Source(section), section)
}

func withSection(name string, section string) string {
	if name == section || strings.Contains(name, "("+section+")") {
		return name
	}
	return name + " (" + section + ")"
}

// uniqueName is the name, or the section without one; with the section in parentheses when
// taken already, and numbered when even that is.
func uniqueName(name string, section string, taken map[string]bool) string {
	if name == "" {
		name = section
	}
	candidate := name
	if taken[candidate] {
		candidate = name + " (" + section + ")"
	}
	for number := 2; taken[candidate]; number++ {
		candidate = name + " (" + section + ") #" + strconv.Itoa(number)
	}
	taken[candidate] = true
	return candidate
}

// oneLine is a text on one line, its spaces single.
func oneLine(text string) string {
	return strings.Join(strings.Fields(text), " ")
}

// autoName is the label of the source, or the name the page gives a source without one.
func (s *Source) autoName() string {
	if label := oneLine(s.Label); label != "" {
		return label
	}
	switch s.Type {
	case "subscription":
		if address, err := url.Parse(strings.TrimSpace(s.URL)); err == nil {
			return address.Hostname()
		}
	case "links":
		links := s.linkList()
		if len(links) == 1 {
			if name := oneLine(linkName(links[0])); name != "" {
				return name
			}
			return strings.TrimSpace(linkScheme(links[0]) + " " + linkHost(links[0]))
		}
		if len(links) > 1 {
			return "My servers"
		}
	case "json":
		var outbound map[string]any
		if json.Unmarshal([]byte(strings.TrimPrefix(strings.TrimSpace(s.OutboundJSON), "\ufeff")), &outbound) == nil {
			for _, key := range []string{"tag", "type"} {
				if text, isText := outbound[key].(string); isText && oneLine(text) != "" {
					return oneLine(text)
				}
			}
		}
	case "interface":
		if s.Interface != "" {
			return s.Interface
		}
		return "Main route"
	}
	return ""
}

// linkList are the links of the source, a value of several links split as the page splits
// them.
func (s *Source) linkList() []string {
	var links []string
	for _, item := range s.Links {
		links = append(links, strings.Fields(item)...)
	}
	return links
}

// linkName is the name of a link after "#".
func linkName(link string) string {
	at := strings.IndexByte(link, '#')
	if at < 0 {
		return ""
	}
	fragment := link[at+1:]
	if unescaped, err := url.PathUnescape(fragment); err == nil {
		return unescaped
	}
	return fragment
}

func linkScheme(link string) string {
	scheme, _, found := strings.Cut(link, "://")
	if !found {
		return ""
	}
	return strings.ToLower(scheme)
}

var linkHostPattern = regexp.MustCompile(`(?i)^[a-z0-9+.-]+://(?:[^@/?#]*@)?(\[[^\]]+\]|[^:/?#]+)(?::(\d+))?`)

// linkHost is the host and port of a link; "" for vmess:// and ss:// links that keep the
// server inside base64.
func linkHost(link string) string {
	match := linkHostPattern.FindStringSubmatch(link)
	if match == nil {
		return ""
	}
	_, rest, _ := strings.Cut(link, "://")
	if !strings.Contains(rest, "@") && (linkScheme(link) == "vmess" || linkScheme(link) == "ss") {
		return ""
	}
	if match[2] != "" {
		return match[1] + ":" + match[2]
	}
	return match[1]
}
