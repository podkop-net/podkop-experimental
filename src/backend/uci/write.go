package uci

import "strings"

// NewSection makes a section for a package: an anonymous one is written without a name, and
// its name here only tells it apart from the others until the file is read again.
func NewSection(sectionType string, name string, anonymous bool) *Section {
	return &Section{Type: sectionType, Name: name, Anonymous: anonymous, options: make(map[string]*option)}
}

// Options returns the names of the options in the order of the file.
func (s *Section) Options() []string {
	return append([]string(nil), s.order...)
}

// IsList tells whether an option is written as a list.
func (s *Section) IsList(name string) bool {
	found := s.options[name]
	return found != nil && found.list
}

// Set sets an option to one value; an option there before keeps its place.
func (s *Section) Set(name string, value string) {
	if s.options[name] == nil {
		s.order = append(s.order, name)
	}
	s.options[name] = &option{values: []string{value}}
}

// SetList sets a list option to the items; no items delete it.
func (s *Section) SetList(name string, values []string) {
	if len(values) == 0 {
		s.Delete(name)
		return
	}
	if s.options[name] == nil {
		s.order = append(s.order, name)
	}
	s.options[name] = &option{list: true, values: append([]string(nil), values...)}
}

// Delete deletes an option.
func (s *Section) Delete(name string) {
	if s.options[name] == nil {
		return
	}
	delete(s.options, name)
	for index, other := range s.order {
		if other == name {
			s.order = append(s.order[:index:index], s.order[index+1:]...)
			break
		}
	}
}

// Format writes the package in the syntax of the files under /etc/config, laid out as
// "uci export" lays it out: every value in single quotes, a quote in a value closed,
// escaped and opened again, so Parse reads back what was written.
func (p *Package) Format() []byte {
	var text strings.Builder
	for index, section := range p.Sections {
		if index > 0 {
			text.WriteByte('\n')
		}
		text.WriteString("config " + section.Type)
		if !section.Anonymous {
			text.WriteString(" " + quote(section.Name))
		}
		text.WriteByte('\n')
		for _, name := range section.order {
			found := section.options[name]
			if !found.list {
				text.WriteString("\toption " + name + " " + quote(found.values[0]) + "\n")
				continue
			}
			for _, value := range found.values {
				text.WriteString("\tlist " + name + " " + quote(value) + "\n")
			}
		}
	}
	return []byte(text.String())
}

func quote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}
