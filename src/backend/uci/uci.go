// Package uci reads a configuration file of OpenWrt's UCI the way libuci does, without the
// uci command: the backend reads its own file on every start, and a test reads fixtures on
// any system. It writes one too (Edit), under the lock libuci takes: the one way the backend
// writes its own settings.
package uci

import (
	"fmt"
	"os"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// Package is one configuration file: the sections in the order of the file.
type Package struct {
	Sections []*Section
}

// Section is a "config <type> '<name>'" block.
type Section struct {
	Type string
	Name string
	// Anonymous is a section written without a name: Name is the one libuci gives it.
	Anonymous bool
	options   map[string]*option
	// order keeps the options in the order of the file, for Format
	order []string
}

type option struct {
	list   bool
	values []string
}

// empty tells an option set to nothing, which libuci does not read: it is as one not set. Here it
// is kept, so that Has tells it from one that is not in the file.
func (o *option) empty() bool { return !o.list && o.values[0] == "" }

// Section returns the section of that name, or nil.
func (p *Package) Section(name string) *Section {
	for _, section := range p.Sections {
		if section.Name == name {
			return section
		}
	}
	return nil
}

// SectionsOfType returns the sections of a type, in the order of the file.
func (p *Package) SectionsOfType(sectionType string) []*Section {
	var sections []*Section
	for _, section := range p.Sections {
		if section.Type == sectionType {
			sections = append(sections, section)
		}
	}
	return sections
}

// Get returns the value of an option the way the shell function config_get gives it: the
// items of a list joined by spaces, and "" for an option that is not set.
func (s *Section) Get(name string) string {
	if s == nil {
		return ""
	}
	found := s.options[name]
	if found == nil {
		return ""
	}
	return strings.Join(found.values, " ")
}

// Has tells whether the option is set.
func (s *Section) Has(name string) bool {
	return s != nil && s.options[name] != nil
}

// List returns the items of a list; an option that is not a list is one item.
func (s *Section) List(name string) []string {
	if s == nil || s.options[name] == nil {
		return nil
	}
	return append([]string(nil), s.options[name].values...)
}

// Bool reads an option as config_get_bool does: the words UCI takes for true and false,
// and the default for anything else.
func (s *Section) Bool(name string, defaultValue bool) bool {
	switch s.Get(name) {
	case "1", "on", "true", "yes", "enabled":
		return true
	case "0", "off", "false", "no", "disabled":
		return false
	}
	return defaultValue
}

// IsOne tells whether a value is the number one as the shell's "-eq 1" reads it: spaces around it,
// a plus sign and zeros before it allowed. The shell backend read some switches so, not as
// config_get_bool does (Bool): "on" and "true" are not one.
func IsOne(text string) bool {
	text = strings.TrimPrefix(strings.Trim(text, " \t\n"), "+")
	if text == "" {
		return false
	}
	for index := 0; index < len(text)-1; index++ {
		if text[index] != '0' {
			return false
		}
	}
	return text[len(text)-1] == '1'
}

// ReadFile reads a configuration file and parses it (Parse).
func ReadFile(path string) (*Package, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(content)
}

// Parse reads the text of a configuration file. A section without a name gets the name
// libuci gives it, as the shell functions see it: "cfg", the number of the section in the
// file and a hash of its type.
func Parse(content []byte) (*Package, error) {
	parser := &parser{text: string(content), line: 1}
	result := new(Package)
	var current *Section
	// sections made so far: a block that names a section already there makes none
	var made int
	for {
		words, err := parser.command()
		if err != nil {
			return nil, err
		}
		if words == nil {
			break
		}
		if len(words) == 0 {
			continue
		}
		line := parser.commandLine
		switch words[0] {
		case "package":
			if len(words) != 2 {
				return nil, E.New("line ", line, ": package takes one name")
			}
		case "config":
			if len(words) < 2 || len(words) > 3 {
				return nil, E.New("line ", line, ": config takes a type and a name")
			}
			if len(words) == 2 || words[2] == "" {
				made++
				current = &Section{Name: anonymousName(made, words[1]), Anonymous: true, options: make(map[string]*option)}
				result.Sections = append(result.Sections, current)
			} else {
				current = result.Section(words[2])
				if current == nil {
					made++
					current = &Section{Name: words[2], options: make(map[string]*option)}
					result.Sections = append(result.Sections, current)
				}
			}
			current.Type = words[1]
		case "option", "list":
			if current == nil {
				return nil, E.New("line ", line, ": ", words[0], " outside of a section")
			}
			if len(words) != 2 && len(words) != 3 {
				return nil, E.New("line ", line, ": ", words[0], " takes a name and a value")
			}
			// no value is an empty one
			value := strings.Join(words[2:], "")
			found := current.options[words[1]]
			if found != nil && words[0] == "option" && value == "" {
				// libuci does not read an option set to nothing: what is there stays
				continue
			}
			if found != nil && found.empty() {
				// nor did it read that one
				current.Delete(words[1])
				found = nil
			}
			if found == nil {
				current.order = append(current.order, words[1])
			}
			if words[0] == "option" || found == nil {
				current.options[words[1]] = &option{list: words[0] == "list", values: []string{value}}
			} else {
				found.list = true
				found.values = append(found.values, value)
			}
		default:
			return nil, E.New("line ", line, ": unknown command ", words[0])
		}
	}
	return result, nil
}

type parser struct {
	text        string
	position    int
	line        int
	commandLine int
}

// command reads the words of the next command: up to the end of the line or a semicolon
// outside of quotes. It returns nil at the end of the text, and no words for an empty line.
func (p *parser) command() ([]string, error) {
	if p.position >= len(p.text) {
		return nil, nil
	}
	words := []string{}
	p.commandLine = p.line
	for p.position < len(p.text) {
		character := p.text[p.position]
		switch character {
		case ' ', '\t', '\r':
			p.position++
		case '\n':
			p.position++
			p.line++
			return words, nil
		case ';':
			p.position++
			return words, nil
		case '#':
			for p.position < len(p.text) && p.text[p.position] != '\n' {
				p.position++
			}
		default:
			if len(words) == 0 {
				p.commandLine = p.line
			}
			word, err := p.word()
			if err != nil {
				return nil, err
			}
			words = append(words, word)
		}
	}
	return words, nil
}

// word reads one argument: pieces that are bare, in single quotes (taken as they are, line
// ends included) or in double quotes (a backslash takes the next character as it is),
// one after another without a space between them.
func (p *parser) word() (string, error) {
	var word strings.Builder
	start := p.line
	for p.position < len(p.text) {
		character := p.text[p.position]
		switch character {
		case ' ', '\t', '\r', '\n', ';', '#':
			return word.String(), nil
		case '\'':
			p.position++
			closed := false
			for p.position < len(p.text) {
				character = p.text[p.position]
				p.position++
				if character == '\'' {
					closed = true
					break
				}
				if character == '\n' {
					p.line++
				}
				word.WriteByte(character)
			}
			if !closed {
				return "", E.New("line ", start, ": a single quote is not closed")
			}
		case '"':
			p.position++
			closed := false
			for p.position < len(p.text) {
				character = p.text[p.position]
				p.position++
				if character == '"' {
					closed = true
					break
				}
				if character == '\\' && p.position < len(p.text) {
					character = p.text[p.position]
					p.position++
					if character == '\n' {
						// a line that goes on
						p.line++
						continue
					}
				}
				if character == '\n' {
					p.line++
				}
				word.WriteByte(character)
			}
			if !closed {
				return "", E.New("line ", start, ": a double quote is not closed")
			}
		case '\\':
			p.position++
			if p.position < len(p.text) {
				if p.text[p.position] == '\n' {
					p.line++
				} else {
					word.WriteByte(p.text[p.position])
				}
				p.position++
			}
		default:
			word.WriteByte(character)
			p.position++
		}
	}
	return word.String(), nil
}

// anonymousName is libuci's name of a section written without one (uci_fixup_section):
// the number of the section among those of the file, in hexadecimal, and sixteen bits of
// a hash of the type. The firewall's zones are cfg02dc81, cfg03dc81 and so on by it.
func anonymousName(number int, sectionType string) string {
	hash := uint32(5381)
	for _, character := range []byte(sectionType) {
		// the C code adds a char: signed on x86 and MIPS, where a byte above 127 counts
		// as negative. Types are ASCII words, so the difference never shows.
		hash = hash*33 + uint32(character)
	}
	return fmt.Sprintf("cfg%02x%04x", number, (hash&0x7FFFFFFF)%65536)
}
