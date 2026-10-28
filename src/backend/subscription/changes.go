package subscription

import (
	"encoding/json"
	"reflect"
	"slices"
	"sort"

	"github.com/podkop-net/podkop-experimental/src/backend/api"
)

// SameList tells whether two lists have the same servers under the same names, in whatever
// order: a list the provider only reordered is the list taken.
func SameList(left []Server, right []Server) bool {
	if len(left) != len(right) {
		return false
	}
	keys := func(servers []Server) []string {
		result := make([]string, len(servers))
		for index := range servers {
			result[index] = identity(&servers[index]) + "\x00" + servers[index].Name
		}
		slices.Sort(result)
		return result
	}
	return slices.Equal(keys(left), keys(right))
}

// identity tells a server apart whatever its name: its ID, and why it cannot be used; the text
// of a link that could not be decoded, which has no ID.
func identity(server *Server) string {
	if server.ID == "" {
		return "\x00" + server.Link
	}
	return server.ID + "\x00" + server.Reason
}

// mostFields is how many changed options Compare names.
const mostFields = 12

// Compare tells how a list differs from the one before: the servers the provider renamed, those
// of a name that are other servers now (and which of their options changed), those taken out
// and those put in. decode gives the outbounds the options are read from.
func Compare(old []Server, fresh []Server, decode Decoder) api.ListChanges {
	var changes api.ListChanges
	// the same server under the same name, then under another one
	oldNames := make(map[string][]string)
	for index := range old {
		key := identity(&old[index])
		oldNames[key] = append(oldNames[key], old[index].Name)
	}
	var unmatched []*Server
	for index := range fresh {
		server := &fresh[index]
		key := identity(server)
		names := oldNames[key]
		if at := slices.Index(names, server.Name); at >= 0 {
			oldNames[key] = slices.Delete(names, at, at+1)
			continue
		}
		unmatched = append(unmatched, server)
	}
	var added []*Server
	for _, server := range unmatched {
		key := identity(server)
		if names := oldNames[key]; len(names) > 0 {
			oldNames[key] = names[1:]
			changes.Renamed++
			continue
		}
		added = append(added, server)
	}
	// what is left of the old list by name: a server of a name that is another one now
	left := make(map[string][]*Server)
	for index := range old {
		server := &old[index]
		key := identity(server)
		if at := slices.Index(oldNames[key], server.Name); at >= 0 {
			oldNames[key] = slices.Delete(oldNames[key], at, at+1)
			left[server.Name] = append(left[server.Name], server)
		}
	}
	fields := make(map[string]bool)
	for _, server := range added {
		before := left[server.Name]
		if len(before) == 0 {
			changes.Added++
			continue
		}
		left[server.Name] = before[1:]
		changes.Changed++
		for _, field := range changedFields(before[0].Link, server.Link, decode) {
			fields[field] = true
		}
	}
	for _, servers := range left {
		changes.Removed += len(servers)
	}
	for field := range fields {
		changes.Fields = append(changes.Fields, field)
	}
	sort.Strings(changes.Fields)
	if len(changes.Fields) > mostFields {
		changes.Fields = append(changes.Fields[:mostFields], "…")
	}
	return changes
}

// changedFields are the options of the outbounds of two links that differ, as paths
// ("tls.server_name"); "link" when a link cannot be decoded.
func changedFields(before string, after string, decode Decoder) []string {
	read := func(link string) map[string]any {
		if decode == nil {
			return nil
		}
		content, _, err := decode(link)
		if err != nil {
			return nil
		}
		var outbound map[string]any
		if json.Unmarshal(content, &outbound) != nil {
			return nil
		}
		delete(outbound, "tag")
		return outbound
	}
	left, right := read(before), read(after)
	if left == nil || right == nil {
		return []string{"link"}
	}
	var fields []string
	diffValues("", left, right, &fields)
	return fields
}

func diffValues(path string, left any, right any, fields *[]string) {
	leftMap, leftIsMap := left.(map[string]any)
	rightMap, rightIsMap := right.(map[string]any)
	if !leftIsMap || !rightIsMap {
		if !reflect.DeepEqual(left, right) {
			*fields = append(*fields, path)
		}
		return
	}
	keys := make(map[string]bool)
	for key := range leftMap {
		keys[key] = true
	}
	for key := range rightMap {
		keys[key] = true
	}
	for key := range keys {
		next := key
		if path != "" {
			next = path + "." + key
		}
		diffValues(next, leftMap[key], rightMap[key], fields)
	}
}
