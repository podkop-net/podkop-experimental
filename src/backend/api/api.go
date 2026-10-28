// Package api is the protocol of the socket the running backend listens on: the types of
// its answers, the server and the client. The commands of the user interface (ctl)
// ask the backend through it; what they need to know of what runs, the backend tells
// (Facts), and they do not work it out again from the settings.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/logbuf"
	E "github.com/sagernet/sing/common/exceptions"
)

// SocketPath is where the running backend listens.
const SocketPath = "/var/run/podkop/ctl.sock"

// ProtocolVersion is the version of this protocol, told in Status. The command line and
// the backend are one program, but between the upgrade of the package and the restart of
// the service the backend that runs is the one before: the version tells why an answer is
// not what the command expects.
const ProtocolVersion = 1

// The files of the directory of the configuration (supervisor.Options.ConfigDir). The
// configuration that runs is there while it runs, and as the last one once it stops,
// until the next one runs; the last configuration sing-box refused is there until the
// next settings are read.
const (
	RunningConfig  = "config.json"
	LastConfig     = "config.last.json"
	RejectedConfig = "config.rejected.json"
)

// Result is what a boot or a change of the settings came to.
type Result struct {
	// OK tells whether the router is now in the state the settings ask for.
	OK bool `json:"ok"`
	// Message says what was done, or why it was not.
	Message string `json:"message"`
}

// Status is the state of the backend.
type Status struct {
	// Protocol is the ProtocolVersion of the backend.
	Protocol int `json:"protocol"`
	// Running tells whether sing-box runs and the router is set up around it.
	Running bool `json:"running"`
	// Since is when the configuration that runs was started.
	Since time.Time `json:"since"`
	// Last is what the last boot or change came to.
	Last Result `json:"last"`
	// LastAt is when that was.
	LastAt time.Time `json:"last_at"`
}

// Facts are what the commands need to know of what runs.
type Facts struct {
	// ClashAPI is where the Clash API of the configuration that runs is reached from the
	// router (host:port), and ClashSecret its key; empty when nothing runs.
	ClashAPI    string `json:"clash_api"`
	ClashSecret string `json:"clash_secret"`
}

// ListsUpdate is what an update of the lists asked for from outside came to.
type ListsUpdate struct {
	// OK tells whether every list that is downloaded was downloaded.
	OK bool `json:"ok"`
	// Lines say what was done, a line a kind of list.
	Lines []string `json:"lines"`
}

// ListState is what is known of one rule set of the configuration that runs.
type ListState struct {
	Tag string `json:"tag"`
	// Kind is who fills the rule set: "remote" — sing-box downloads it from URL, in
	// Format (a list written as plain text is "text"); "file" — the backend writes the
	// file at Path from the settings or a local list.
	Kind   string `json:"kind"`
	URL    string `json:"url,omitempty"`
	Format string `json:"format,omitempty"`
	Path   string `json:"path,omitempty"`
	// LastUpdated is when sing-box last downloaded a remote rule set or found it
	// unchanged at its server; none before the first download.
	LastUpdated *time.Time `json:"last_updated,omitempty"`
}

// ProbeResult is what the backend saw of a check name.
type ProbeResult struct {
	// DNS tells that a DNS question for the name was answered from FakeIP.
	DNS bool `json:"dns"`
	// Connection tells that a connection to the name came in through the transparent
	// proxy inbound: past the firewall mark and the routing table.
	Connection bool `json:"connection"`
	// Client is the address the connection came from.
	Client string `json:"client,omitempty"`
	// Address is the FakeIP address of the name.
	Address string `json:"address,omitempty"`
}

// LogPage is a part of the log: lines, the number to ask with for what comes after, and
// the run of the backend the numbers belong to.
type LogPage struct {
	Run   string   `json:"run"`
	Next  uint64   `json:"next"`
	Lines []string `json:"lines"`
}

// SubscriptionState is what is known of a subscription of the settings.
type SubscriptionState struct {
	Name string `json:"name"`
	// Servers is the number of servers of the list taken, Usable of those sing-box can use.
	Servers int `json:"servers"`
	Usable  int `json:"usable"`
	// Changed is when the list taken was downloaded; Checked when a download last brought
	// a list, changed or not; Route the way it came.
	Changed *time.Time `json:"changed,omitempty"`
	Checked *time.Time `json:"checked,omitempty"`
	Route   string     `json:"route,omitempty"`
	// Error is why the last download failed; empty when it did not. ErrorCode and ErrorArgs
	// are the same for the page to translate.
	Error     string   `json:"error,omitempty"`
	ErrorCode string   `json:"error_code,omitempty"`
	ErrorArgs []string `json:"error_args,omitempty"`
	// Attempted is when the last download ended, whatever it came to; Took how long the last
	// one that brought a list took; Attempts the tries of the last download.
	Attempted *time.Time `json:"attempted,omitempty"`
	Took      int64      `json:"took_ms,omitempty"`
	Attempts  []Attempt  `json:"attempts,omitempty"`
	// Next is when the next download is due; Busy tells that one is under way.
	Next *time.Time `json:"next,omitempty"`
	Busy bool       `json:"busy,omitempty"`
	// Provider is what the provider told of the subscription with the last list.
	Provider *ProviderInfo `json:"provider,omitempty"`
	// Now is the time of the router: the page counts how long ago by it.
	Now *time.Time `json:"now,omitempty"`
}

// Attempt is a try of a download by one way: the way, how far it came (connect, tls, wait,
// body, done, failed, canceled), how long it took and how much came, and why it failed (the
// English text, and a code with its arguments for the page).
type Attempt struct {
	Route     string   `json:"route"`
	Phase     string   `json:"phase"`
	Took      int64    `json:"ms"`
	FirstByte int64    `json:"first_byte_ms,omitempty"`
	Bytes     int64    `json:"bytes,omitempty"`
	Error     string   `json:"error,omitempty"`
	Code      string   `json:"code,omitempty"`
	Args      []string `json:"args,omitempty"`
}

// LoadJob is a download of a list for the page (Load), under way or done: the page starts
// it and asks how it goes, so the download is not bound by how long LuCI waits for a call.
type LoadJob struct {
	ID string `json:"id"`
	// State is running, done, failed or canceled.
	State    string    `json:"state"`
	Elapsed  int64     `json:"elapsed_ms"`
	Attempts []Attempt `json:"attempts"`
	// Preview is what the download came to, once it ended.
	Preview *SubscriptionPreview `json:"preview,omitempty"`
}

// ProviderInfo is what a provider tells of a subscription in the headers of its list
// (subscription-userinfo, profile-title and the like), checked: the page shows it as text.
type ProviderInfo struct {
	Title string `json:"title,omitempty"`
	// Upload and Download are the bytes used so far; Total is the limit, 0 when there is none.
	Upload   int64 `json:"upload,omitempty"`
	Download int64 `json:"download,omitempty"`
	Total    int64 `json:"total,omitempty"`
	// Traffic tells that the provider told the traffic at all (all of it may be 0).
	Traffic bool `json:"traffic,omitempty"`
	// Expire is when the subscription ends; none when it does not, or is not told.
	Expire *time.Time `json:"expire,omitempty"`
	// Refill is when the traffic is counted from 0 again (subscription-refill-date).
	Refill *time.Time `json:"refill,omitempty"`
	// UpdateHours is how often the provider asks the list to be downloaded again.
	UpdateHours int `json:"update_hours,omitempty"`
	// SupportURL and WebPageURL are pages of the provider (HTTP or HTTPS only).
	SupportURL string `json:"support_url,omitempty"`
	WebPageURL string `json:"web_page_url,omitempty"`
	// Announce is a notice of the provider to its users.
	Announce string `json:"announce,omitempty"`
}

// SubscriptionPreview is a list downloaded to be shown, not taken.
type SubscriptionPreview struct {
	// Route is the way it came; Error why no list came, ErrorCode and ErrorArgs the same for
	// the page to translate; Took how long it took; Attempts the tries of the download.
	Route     string          `json:"route,omitempty"`
	Error     string          `json:"error,omitempty"`
	ErrorCode string          `json:"error_code,omitempty"`
	ErrorArgs []string        `json:"error_args,omitempty"`
	Took      int64           `json:"took_ms,omitempty"`
	Attempts  []Attempt       `json:"attempts,omitempty"`
	Servers   []PreviewServer `json:"servers"`
	// Provider is what the provider told of the subscription with the list.
	Provider *ProviderInfo `json:"provider,omitempty"`
}

// PreviewServer is a server of a list as the page shows it.
type PreviewServer struct {
	Name string `json:"name"`
	// Scheme and Address (host:port) are of its link, which Link is, a secret shown to the
	// user who asked.
	Scheme  string `json:"scheme"`
	Address string `json:"address,omitempty"`
	Link    string `json:"link"`
	// Reason is why sing-box cannot use it; Notes what of the link it leaves out.
	Reason string   `json:"reason,omitempty"`
	Notes  []string `json:"notes,omitempty"`
}

// GroupCheck asks which servers a group would choose: the group as the form has it, not
// as the settings saved it. Addresses are those of its subscriptions in the form, by name:
// a subscription not saved yet has its address there only.
type GroupCheck struct {
	Subscriptions []string          `json:"subscriptions"`
	Include       []string          `json:"include"`
	Exclude       []string          `json:"exclude"`
	Addresses     map[string]string `json:"addresses,omitempty"`
}

// GroupPreview is which servers a group would choose.
type GroupPreview struct {
	// Chosen are the names of the servers it chooses, in the order of the group; Total is
	// the number of servers of its subscriptions sing-box can use.
	Chosen []string `json:"chosen"`
	Total  int      `json:"total"`
	// Missing are the subscriptions that have no list (with why, when known).
	Missing []string `json:"missing,omitempty"`
}

// Backend is the running backend as the socket shows it.
type Backend interface {
	Status() Status
	// Facts tells what the commands need to know of what runs.
	Facts() Facts
	// Request applies the settings and returns what that came to.
	Request(ctx context.Context) Result
	// UpdateLists downloads every list now and returns what that came to.
	UpdateLists(ctx context.Context) ListsUpdate
	// ListStatus tells what is known of each list of what runs.
	ListStatus(ctx context.Context) []ListState
	// RestoreRouting puts back what the network took and tells what it did.
	RestoreRouting(ctx context.Context) string
	// Probe tells what was seen of the check name of a label, waiting for it.
	Probe(ctx context.Context, label string, wait time.Duration) ProbeResult
	// ProbeSelf checks the router itself with a check name.
	ProbeSelf(ctx context.Context) ProbeResult
	// Subscriptions tells what is known of each subscription.
	Subscriptions(ctx context.Context) []SubscriptionState
	// UpdateSubscriptions downloads the list of a subscription now, or of all of them with
	// no name, and returns what is known of them then.
	UpdateSubscriptions(ctx context.Context, name string) []SubscriptionState
	// LoadSubscription downloads a list from an address to be shown.
	LoadSubscription(ctx context.Context, address string) SubscriptionPreview
	// StartLoad starts a download of a list from an address to be shown; LoadState tells how
	// it goes, CancelLoad stops it. A job not known tells false.
	StartLoad(ctx context.Context, address string) LoadJob
	LoadState(ctx context.Context, id string) (LoadJob, bool)
	CancelLoad(ctx context.Context, id string) (LoadJob, bool)
	// CheckGroup tells which servers a group would choose.
	CheckGroup(ctx context.Context, check GroupCheck) GroupPreview
}

// Serve listens on the socket until the context ends. The socket is for root only: who
// can write to it can make the backend apply the settings, and Facts has the key of the
// Clash API.
func Serve(ctx context.Context, path string, backend Backend, logs *logbuf.Buffer) error {
	err := os.MkdirAll(filepath.Dir(path), 0o755)
	if err != nil {
		return err
	}
	// a socket left by a backend that was killed
	_ = os.Remove(path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		return E.Cause(err, "listen on ", path)
	}
	_ = os.Chmod(path, 0o600)
	answer := func(writer http.ResponseWriter, value any) {
		var encoded bytes.Buffer
		if err := json.NewEncoder(&encoded).Encode(value); err != nil {
			http.Error(writer, "the answer cannot be encoded: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(encoded.Bytes())
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(writer http.ResponseWriter, request *http.Request) {
		status := backend.Status()
		status.Protocol = ProtocolVersion
		answer(writer, status)
	})
	mux.HandleFunc("GET /facts", func(writer http.ResponseWriter, request *http.Request) {
		answer(writer, backend.Facts())
	})
	mux.HandleFunc("GET /logs", func(writer http.ResponseWriter, request *http.Request) {
		since, _ := strconv.ParseUint(request.URL.Query().Get("since"), 10, 64)
		lines, next := logs.Since(since)
		page := LogPage{Run: logs.Run(), Next: next, Lines: make([]string, len(lines))}
		for index, line := range lines {
			page.Lines[index] = line.Text()
		}
		answer(writer, page)
	})
	mux.HandleFunc("POST /apply", func(writer http.ResponseWriter, request *http.Request) {
		answer(writer, backend.Request(request.Context()))
	})
	mux.HandleFunc("POST /lists/update", func(writer http.ResponseWriter, request *http.Request) {
		answer(writer, backend.UpdateLists(request.Context()))
	})
	mux.HandleFunc("GET /lists", func(writer http.ResponseWriter, request *http.Request) {
		answer(writer, backend.ListStatus(request.Context()))
	})
	mux.HandleFunc("POST /routing/restore", func(writer http.ResponseWriter, request *http.Request) {
		answer(writer, backend.RestoreRouting(request.Context()))
	})
	mux.HandleFunc("GET /probe", func(writer http.ResponseWriter, request *http.Request) {
		wait, _ := strconv.Atoi(request.URL.Query().Get("wait"))
		answer(writer, backend.Probe(request.Context(), request.URL.Query().Get("label"), time.Duration(wait)*time.Millisecond))
	})
	mux.HandleFunc("GET /probe/self", func(writer http.ResponseWriter, request *http.Request) {
		answer(writer, backend.ProbeSelf(request.Context()))
	})
	mux.HandleFunc("GET /subscriptions", func(writer http.ResponseWriter, request *http.Request) {
		answer(writer, backend.Subscriptions(request.Context()))
	})
	mux.HandleFunc("POST /subscriptions/update", func(writer http.ResponseWriter, request *http.Request) {
		answer(writer, backend.UpdateSubscriptions(request.Context(), request.URL.Query().Get("name")))
	})
	mux.HandleFunc("POST /subscriptions/load", func(writer http.ResponseWriter, request *http.Request) {
		var asked struct {
			Address string `json:"address"`
		}
		if json.NewDecoder(io.LimitReader(request.Body, 64<<10)).Decode(&asked) != nil {
			http.Error(writer, "the request is not JSON", http.StatusBadRequest)
			return
		}
		answer(writer, backend.LoadSubscription(request.Context(), asked.Address))
	})
	mux.HandleFunc("POST /subscriptions/load/start", func(writer http.ResponseWriter, request *http.Request) {
		var asked struct {
			Address string `json:"address"`
		}
		if json.NewDecoder(io.LimitReader(request.Body, 64<<10)).Decode(&asked) != nil {
			http.Error(writer, "the request is not JSON", http.StatusBadRequest)
			return
		}
		answer(writer, backend.StartLoad(request.Context(), asked.Address))
	})
	mux.HandleFunc("GET /subscriptions/load/state", func(writer http.ResponseWriter, request *http.Request) {
		job, known := backend.LoadState(request.Context(), request.URL.Query().Get("id"))
		if !known {
			http.Error(writer, "no such download", http.StatusNotFound)
			return
		}
		answer(writer, job)
	})
	mux.HandleFunc("POST /subscriptions/load/cancel", func(writer http.ResponseWriter, request *http.Request) {
		job, known := backend.CancelLoad(request.Context(), request.URL.Query().Get("id"))
		if !known {
			http.Error(writer, "no such download", http.StatusNotFound)
			return
		}
		answer(writer, job)
	})
	mux.HandleFunc("POST /groups/check", func(writer http.ResponseWriter, request *http.Request) {
		var check GroupCheck
		if json.NewDecoder(io.LimitReader(request.Body, 64<<10)).Decode(&check) != nil {
			http.Error(writer, "the request is not JSON", http.StatusBadRequest)
			return
		}
		answer(writer, backend.CheckGroup(request.Context(), check))
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		_ = server.Close()
		_ = os.Remove(path)
	}()
	err = server.Serve(listener)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// Client asks a running backend through its socket.
type Client struct {
	Path string
}

func (c Client) call(method string, path string, timeout time.Duration, result any) error {
	return c.send(method, path, timeout, nil, result)
}

// send is call with a body of JSON, when body is not nil.
func (c Client) send(method string, path string, timeout time.Duration, body any, result any) error {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", c.Path)
		},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var content io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		content = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://backend"+path, content)
	if err != nil {
		return err
	}
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return E.New("the backend answers ", response.Status)
	}
	return json.NewDecoder(response.Body).Decode(result)
}

// Status returns the state of the backend; an error when none runs.
func (c Client) Status() (*Status, error) {
	status := new(Status)
	err := c.call(http.MethodGet, "/status", 3*time.Second, status)
	if err != nil {
		return nil, err
	}
	return status, nil
}

// Facts returns what the commands need to know of what runs; an error when no backend
// runs.
func (c Client) Facts() (*Facts, error) {
	facts := new(Facts)
	err := c.call(http.MethodGet, "/facts", 3*time.Second, facts)
	if err != nil {
		return nil, err
	}
	return facts, nil
}

// Logs returns the lines of the log after the given number, and the number to ask with next.
func (c Client) Logs(since uint64) (*LogPage, error) {
	page := new(LogPage)
	err := c.call(http.MethodGet, "/logs?since="+strconv.FormatUint(since, 10), 5*time.Second, page)
	if err != nil {
		return nil, err
	}
	return page, nil
}

// Apply makes the backend apply the settings and returns what that came to.
func (c Client) Apply() (*Result, error) {
	result := new(Result)
	err := c.call(http.MethodPost, "/apply", 90*time.Second, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// UpdateLists makes the backend download every list now and returns what that came to.
func (c Client) UpdateLists() (*ListsUpdate, error) {
	result := new(ListsUpdate)
	err := c.call(http.MethodPost, "/lists/update", 6*time.Minute, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// RestoreRouting asks the backend to put back what the network took, and returns what it
// did.
func (c Client) RestoreRouting() (string, error) {
	var result string
	err := c.call(http.MethodPost, "/routing/restore", 10*time.Second, &result)
	return result, err
}

// Lists returns what the backend knows of each list of what runs.
func (c Client) Lists() ([]ListState, error) {
	var states []ListState
	err := c.call(http.MethodGet, "/lists", 10*time.Second, &states)
	if err != nil {
		return nil, err
	}
	return states, nil
}

// Probe asks the backend what it saw of the check name of a label; the backend waits for
// the connection for the given time, its usual one when that is zero.
func (c Client) Probe(label string, wait time.Duration) (*ProbeResult, error) {
	result := new(ProbeResult)
	path := "/probe?label=" + url.QueryEscape(label) + "&wait=" + strconv.FormatInt(wait.Milliseconds(), 10)
	// LuCI gives up a call after 20 s: global_check waits for this beside its other checks
	err := c.call(http.MethodGet, path, wait+8*time.Second, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ProbeSelf makes the backend check the router itself with a check name.
func (c Client) ProbeSelf() (*ProbeResult, error) {
	result := new(ProbeResult)
	err := c.call(http.MethodGet, "/probe/self", 15*time.Second, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Subscriptions returns what the backend knows of each subscription.
func (c Client) Subscriptions() ([]SubscriptionState, error) {
	var states []SubscriptionState
	err := c.call(http.MethodGet, "/subscriptions", 5*time.Second, &states)
	return states, err
}

// UpdateSubscriptions makes the backend download the list of a subscription now (all of
// them with no name) and returns what it knows of them then.
func (c Client) UpdateSubscriptions(name string) ([]SubscriptionState, error) {
	var states []SubscriptionState
	err := c.call(http.MethodPost, "/subscriptions/update?name="+url.QueryEscape(name), 3*time.Minute, &states)
	return states, err
}

// LoadSubscription makes the backend download a list from an address to be shown.
func (c Client) LoadSubscription(address string, timeout time.Duration) (*SubscriptionPreview, error) {
	preview := new(SubscriptionPreview)
	err := c.send(http.MethodPost, "/subscriptions/load", timeout, map[string]string{"address": address}, preview)
	if err != nil {
		return nil, err
	}
	return preview, nil
}

// StartLoad makes the backend start a download of a list from an address to be shown.
func (c Client) StartLoad(address string) (*LoadJob, error) {
	job := new(LoadJob)
	err := c.send(http.MethodPost, "/subscriptions/load/start", 5*time.Second, map[string]string{"address": address}, job)
	if err != nil {
		return nil, err
	}
	return job, nil
}

// LoadState asks the backend how a download of a list for the page goes.
func (c Client) LoadState(id string) (*LoadJob, error) {
	job := new(LoadJob)
	err := c.call(http.MethodGet, "/subscriptions/load/state?id="+url.QueryEscape(id), 5*time.Second, job)
	if err != nil {
		return nil, err
	}
	return job, nil
}

// CancelLoad makes the backend stop a download of a list for the page.
func (c Client) CancelLoad(id string) (*LoadJob, error) {
	job := new(LoadJob)
	err := c.call(http.MethodPost, "/subscriptions/load/cancel?id="+url.QueryEscape(id), 5*time.Second, job)
	if err != nil {
		return nil, err
	}
	return job, nil
}

// CheckGroup asks the backend which servers a group would choose.
func (c Client) CheckGroup(check GroupCheck, timeout time.Duration) (*GroupPreview, error) {
	preview := new(GroupPreview)
	err := c.send(http.MethodPost, "/groups/check", timeout, check, preview)
	if err != nil {
		return nil, err
	}
	return preview, nil
}
