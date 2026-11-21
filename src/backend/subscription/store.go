package subscription

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// Saved is the list of a subscription as it was last taken.
type Saved struct {
	// Address is the hash of the address the list came from (AddressKey): a list of an
	// address the settings no longer have is not used.
	Address string `json:"address"`
	// Changed is when the list was taken.
	Changed time.Time `json:"changed"`
	// Route is the way it came: "direct" or the tag of an outbound.
	Route   string   `json:"route,omitempty"`
	Servers []Server `json:"servers"`
	// Info are the headers the provider tells about the subscription with (traffic, its
	// end, the interval it asks for), as they were then.
	Info map[string]string `json:"info,omitempty"`
	// Format is what the list came as: "" a list of links (a list kept before formats were
	// read too), FormatXray or FormatSingBox, whose servers podkop made links of; Configs is the
	// number of the configurations of Xray JSON.
	Format  string `json:"format,omitempty"`
	Configs int    `json:"configs,omitempty"`

	// outbounds is how many outbounds of servers the configurations had, for the log
	outbounds int
}

// Outbounds is how many outbounds of servers the configurations of the list had when it was
// downloaded (0 for a list kept on flash).
func (s *Saved) Outbounds() int {
	return s.outbounds
}

// SavedList is the list to keep of what the provider sent.
func SavedList(list List) *Saved {
	return &Saved{Servers: list.Servers, Format: list.Format, Configs: list.Configs, outbounds: list.Outbounds}
}

// Verdicts are the reasons of the servers of the list by their ID (Check).
func (s *Saved) Verdicts() map[string]string {
	verdicts := make(map[string]string)
	for _, server := range s.Servers {
		if server.ID != "" {
			verdicts[server.ID] = server.Reason
		}
	}
	return verdicts
}

// AddressKey is what a list keeps of the address it came from.
func AddressKey(address string) string {
	sum := sha256.Sum256([]byte(address))
	return hex.EncodeToString(sum[:16])
}

// SameServers tells whether two lists have the same servers, whatever their names and their
// order: a list that changed only so is not taken, and the configuration stays as it is.
func SameServers(left []Server, right []Server) bool {
	if len(left) != len(right) {
		return false
	}
	keys := func(servers []Server) []string {
		result := make([]string, len(servers))
		for index := range servers {
			// a link that could not be decoded has no ID: its text tells it, or for a server of a
			// configuration podkop made no link of, its name and its reason
			result[index] = identity(&servers[index])
		}
		slices.Sort(result)
		return result
	}
	return slices.Equal(keys(left), keys(right))
}

// Store keeps the lists of the subscriptions in a directory, a file a subscription, which
// only root reads: the links are secrets. It is on flash, so that a start without the
// network has the servers, and a file is written only when its list changed.
type Store struct {
	Dir string
}

func (s Store) path(name string) string {
	return filepath.Join(s.Dir, name+".json")
}

// Load returns the list kept for a subscription of the name and the address; none when
// there is none, or it came from another address.
func (s Store) Load(name string, address string) (*Saved, bool) {
	content, err := os.ReadFile(s.path(name))
	if err != nil {
		return nil, false
	}
	saved := new(Saved)
	if json.Unmarshal(content, saved) != nil || saved.Address != AddressKey(address) {
		return nil, false
	}
	return saved, true
}

// Save keeps the list of a subscription in place of the one there was.
func (s Store) Save(name string, saved *Saved) error {
	err := os.MkdirAll(s.Dir, 0o700)
	if err != nil {
		return E.Cause(err, "make the directory of the subscriptions")
	}
	content, err := json.Marshal(saved)
	if err != nil {
		return E.Cause(err, "encode the list of ", name)
	}
	file, err := os.CreateTemp(s.Dir, "."+name+".*")
	if err != nil {
		return E.Cause(err, "write the list of ", name)
	}
	defer os.Remove(file.Name())
	_, err = file.Write(content)
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(file.Name(), s.path(name))
	}
	if err != nil {
		return E.Cause(err, "write the list of ", name)
	}
	return nil
}

// Keep removes the lists of the subscriptions that are not named: those the settings no
// longer have.
func (s Store) Keep(names []string) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name, isList := strings.CutSuffix(entry.Name(), ".json")
		if isList && !strings.HasPrefix(name, ".") && !slices.Contains(names, name) {
			_ = os.Remove(filepath.Join(s.Dir, entry.Name()))
		}
	}
}
