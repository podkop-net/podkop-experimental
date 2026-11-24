// Package api is the protocol of the socket the running backend listens on: the types of
// its answers, the server and the client. The commands of the user interface (ctl)
// ask the backend through it, or with no socket those the backend answers itself (Direct);
// what they need to know of what runs, the backend tells (Facts), and they do not work it
// out again from the settings.
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
	"unicode/utf8"

	"github.com/podkop-net/podkop-experimental/src/backend/btstats"
	"github.com/podkop-net/podkop-experimental/src/backend/logbuf"
	"github.com/podkop-net/podkop-experimental/src/backend/subscription"
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
	// Tags tell what the outbounds of the configuration that runs are (plan.Tags), as JSON:
	// their tags are made of the names of the rules and the sources.
	Tags json.RawMessage `json:"tags,omitempty"`
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
	Provider *subscription.ProviderInfo `json:"provider,omitempty"`
	// Changes are how the list taken differs from the one before it (Changed).
	Changes *subscription.ListChanges `json:"changes,omitempty"`
	// Agent is the User-Agent of the settings the list is asked with ("": podkop's own), Preset
	// the app it is the User-Agent of ("happ", "incy", "sing-box"; "" for podkop's own and for
	// one typed in the settings), Headers the names of their extra headers (never the values),
	// Problems the lines of the settings left out of the request.
	Agent    string           `json:"agent,omitempty"`
	Preset   string           `json:"preset,omitempty"`
	Headers  []string         `json:"headers,omitempty"`
	Problems []RequestProblem `json:"request_problems,omitempty"`
	// Format is what the list taken came as: "" a list of links, "xray" or "sing-box" a
	// configuration whose servers podkop made links of; Configs the number of the configurations
	// of Xray JSON.
	Format  string `json:"format,omitempty"`
	Configs int    `json:"configs,omitempty"`
	// Now is the time of the router: the page counts how long ago by it.
	Now *time.Time `json:"now,omitempty"`
}

// ListRequest is what a subscription is asked with besides its address: the preset of the
// User-Agent (podkop, happ, incy, sing-box, custom), the User-Agent of custom and the extra
// headers (Name: value) of the settings, or of the form of the page not saved yet. A User-Agent
// without a preset is custom.
type ListRequest struct {
	Preset    string   `json:"user_agent_preset,omitempty"`
	UserAgent string   `json:"user_agent,omitempty"`
	Headers   []string `json:"headers,omitempty"`
}

// RequestProblem is a line of the settings left out of the request: its number among the header
// lines (0 for the User-Agent), the name of the header when it is one, and why (a code with its
// arguments for the page, and the English text). It never holds a value.
type RequestProblem struct {
	Line int      `json:"line"`
	Name string   `json:"name,omitempty"`
	Code string   `json:"code"`
	Args []string `json:"args,omitempty"`
	Text string   `json:"text"`
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
	Provider *subscription.ProviderInfo `json:"provider,omitempty"`
	// Agent is the User-Agent the list was asked with ("": podkop's own), Preset the app it is
	// the User-Agent of ("" for podkop's own and for another one).
	Agent  string `json:"agent,omitempty"`
	Preset string `json:"preset,omitempty"`
	// Format is what the list came as ("" links, "xray", "sing-box"), Configs the number of the
	// configurations of Xray JSON.
	Format  string `json:"format,omitempty"`
	Configs int    `json:"configs,omitempty"`
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
	// Made tells that podkop made the link of the server of a configuration (Xray or sing-box
	// JSON): other apps may read it otherwise.
	Made bool `json:"made,omitempty"`
}

// GroupCheck asks which servers a group would choose: the group as the form has it, not
// as the settings saved it. Addresses are those of its subscriptions in the form, by name:
// a subscription not saved yet has its address there only. Requests are the User-Agent and
// the headers of its subscriptions as the page has them, by name; one not there is asked as
// the settings that run ask it. Include, Exclude and Protocols are those of a row (model.Member).
type GroupCheck struct {
	Subscriptions []string               `json:"subscriptions"`
	Include       []string               `json:"include"`
	Exclude       []string               `json:"exclude"`
	Protocols     []string               `json:"protocols,omitempty"`
	Addresses     map[string]string      `json:"addresses,omitempty"`
	Requests      map[string]ListRequest `json:"requests,omitempty"`
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
	// LoadSubscription downloads a list from an address, asked with the request, to be shown.
	LoadSubscription(ctx context.Context, address string, request ListRequest) SubscriptionPreview
	// StartLoad starts a download of a list from an address, asked with the request, to be
	// shown; LoadState tells how it goes, CancelLoad stops it. A job not known tells false.
	StartLoad(ctx context.Context, address string, request ListRequest) LoadJob
	LoadState(ctx context.Context, id string) (LoadJob, bool)
	CancelLoad(ctx context.Context, id string) (LoadJob, bool)
	// CheckGroup tells which servers a group would choose.
	CheckGroup(ctx context.Context, check GroupCheck) GroupPreview
	// BitTorrent is what the BitTorrent module of the running sing-box has counted, by name;
	// nil when none runs.
	BitTorrent() map[string]int64
	// BitTorrentStats is what the BitTorrent traffic of the LAN came to, by its kind and its way.
	BitTorrentStats() btstats.Report
	// ResetBitTorrentStats starts those statistics again from now and answers them.
	ResetBitTorrentStats() btstats.Report
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
		answer(writer, statusOf(backend))
	})
	mux.HandleFunc("GET /facts", func(writer http.ResponseWriter, request *http.Request) {
		answer(writer, backend.Facts())
	})
	mux.HandleFunc("GET /logs", func(writer http.ResponseWriter, request *http.Request) {
		since, _ := strconv.ParseUint(request.URL.Query().Get("since"), 10, 64)
		answer(writer, logPage(logs, since))
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
	mux.HandleFunc("GET /bittorrent", func(writer http.ResponseWriter, request *http.Request) {
		answer(writer, backend.BitTorrent())
	})
	mux.HandleFunc("GET /bittorrent/stats", func(writer http.ResponseWriter, request *http.Request) {
		answer(writer, backend.BitTorrentStats())
	})
	mux.HandleFunc("POST /bittorrent/stats/reset", func(writer http.ResponseWriter, request *http.Request) {
		answer(writer, backend.ResetBitTorrentStats())
	})
	mux.HandleFunc("GET /subscriptions", func(writer http.ResponseWriter, request *http.Request) {
		answer(writer, backend.Subscriptions(request.Context()))
	})
	mux.HandleFunc("POST /subscriptions/update", func(writer http.ResponseWriter, request *http.Request) {
		name := request.URL.Query().Get("name")
		if request.URL.Query().Get("wait") == "0" {
			answer(writer, startUpdate(request.Context(), backend, name))
			return
		}
		answer(writer, backend.UpdateSubscriptions(request.Context(), name))
	})
	mux.HandleFunc("POST /subscriptions/load", func(writer http.ResponseWriter, request *http.Request) {
		var asked loadAsked
		if json.NewDecoder(io.LimitReader(request.Body, 64<<10)).Decode(&asked) != nil {
			http.Error(writer, "the request is not JSON", http.StatusBadRequest)
			return
		}
		answer(writer, backend.LoadSubscription(request.Context(), asked.Address, asked.ListRequest))
	})
	mux.HandleFunc("POST /subscriptions/load/start", func(writer http.ResponseWriter, request *http.Request) {
		var asked loadAsked
		if json.NewDecoder(io.LimitReader(request.Body, 64<<10)).Decode(&asked) != nil {
			http.Error(writer, "the request is not JSON", http.StatusBadRequest)
			return
		}
		answer(writer, backend.StartLoad(request.Context(), asked.Address, asked.ListRequest))
	})
	mux.HandleFunc("GET /subscriptions/load/state", func(writer http.ResponseWriter, request *http.Request) {
		job, known := backend.LoadState(request.Context(), request.URL.Query().Get("id"))
		if !known {
			http.Error(writer, errNoJob.Error(), http.StatusNotFound)
			return
		}
		answer(writer, job)
	})
	mux.HandleFunc("POST /subscriptions/load/cancel", func(writer http.ResponseWriter, request *http.Request) {
		job, known := backend.CancelLoad(request.Context(), request.URL.Query().Get("id"))
		if !known {
			http.Error(writer, errNoJob.Error(), http.StatusNotFound)
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

// statusOf is the state of the backend, with the version of this protocol.
func statusOf(backend Backend) *Status {
	status := backend.Status()
	status.Protocol = ProtocolVersion
	return &status
}

// logPage is the part of the log after the line of a number. A byte that is no UTF-8 (what a client
// sent, in a line of sing-box) is U+FFFD, as JSON makes it: the readers count the size of the lines.
func logPage(logs *logbuf.Buffer, since uint64) *LogPage {
	lines, next := logs.Since(since)
	page := &LogPage{Run: logs.Run(), Next: next, Lines: make([]string, len(lines))}
	for index, line := range lines {
		text := line.Text()
		if !utf8.ValidString(text) {
			text = string([]rune(text))
		}
		page.Lines[index] = text
	}
	return page
}

// startUpdate starts the download of a subscription and tells the states at once: the page asks
// for them again until the download has ended.
func startUpdate(ctx context.Context, backend Backend, name string) []SubscriptionState {
	ctx, cancel := context.WithTimeout(ctx, startWait)
	defer cancel()
	return backend.UpdateSubscriptions(ctx, name)
}

// errNoJob tells that the backend knows no job of an id.
var errNoJob = E.New("no such download")

// loadAsked is the body of a download of a list for the page: the address and the request. A
// backend before the request had one reads the address alone.
type loadAsked struct {
	Address string `json:"address"`
	ListRequest
}

// How long Client and Direct wait for the answers of the backend.
const (
	factsWait       = 3 * time.Second
	stateWait       = 5 * time.Second
	listsWait       = 10 * time.Second
	probeSelfWait   = 15 * time.Second
	applyWait       = 90 * time.Second
	updateListsWait = 6 * time.Minute
	updateWait      = 3 * time.Minute
	// probeSlack is how much longer than the backend waits for a connection its answer is waited
	// for. LuCI gives up a call after 20 s: global_check waits for this beside its other checks.
	probeSlack = 8 * time.Second
	// startWait is how long a start of a download (StartSubscriptionUpdate) waits for the backend
	// to take the request: the download itself goes on without the caller.
	startWait = 2 * time.Second
)

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
	err := c.call(http.MethodGet, "/status", factsWait, status)
	if err != nil {
		return nil, err
	}
	return status, nil
}

// Facts returns what the commands need to know of what runs; an error when no backend
// runs.
func (c Client) Facts() (*Facts, error) {
	facts := new(Facts)
	err := c.call(http.MethodGet, "/facts", factsWait, facts)
	if err != nil {
		return nil, err
	}
	return facts, nil
}

// Logs returns the lines of the log after the given number, and the number to ask with next.
func (c Client) Logs(since uint64) (*LogPage, error) {
	page := new(LogPage)
	err := c.call(http.MethodGet, "/logs?since="+strconv.FormatUint(since, 10), stateWait, page)
	if err != nil {
		return nil, err
	}
	return page, nil
}

// Apply makes the backend apply the settings and returns what that came to.
func (c Client) Apply() (*Result, error) {
	result := new(Result)
	err := c.call(http.MethodPost, "/apply", applyWait, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// UpdateLists makes the backend download every list now and returns what that came to.
func (c Client) UpdateLists() (*ListsUpdate, error) {
	result := new(ListsUpdate)
	err := c.call(http.MethodPost, "/lists/update", updateListsWait, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// RestoreRouting asks the backend to put back what the network took, and returns what it
// did.
func (c Client) RestoreRouting() (string, error) {
	var result string
	err := c.call(http.MethodPost, "/routing/restore", listsWait, &result)
	return result, err
}

// Lists returns what the backend knows of each list of what runs.
func (c Client) Lists() ([]ListState, error) {
	var states []ListState
	err := c.call(http.MethodGet, "/lists", listsWait, &states)
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
	err := c.call(http.MethodGet, path, wait+probeSlack, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ProbeSelf makes the backend check the router itself with a check name.
func (c Client) ProbeSelf() (*ProbeResult, error) {
	result := new(ProbeResult)
	err := c.call(http.MethodGet, "/probe/self", probeSelfWait, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// BitTorrentStats returns what the BitTorrent traffic of the LAN came to.
func (c Client) BitTorrentStats() (btstats.Report, error) {
	var report btstats.Report
	err := c.call(http.MethodGet, "/bittorrent/stats", stateWait, &report)
	return report, err
}

// ResetBitTorrentStats starts the statistics of BitTorrent again and returns them.
func (c Client) ResetBitTorrentStats() (btstats.Report, error) {
	var report btstats.Report
	err := c.call(http.MethodPost, "/bittorrent/stats/reset", stateWait, &report)
	return report, err
}

// BitTorrent returns what the BitTorrent module has counted (nil when it does not run).
func (c Client) BitTorrent() (map[string]int64, error) {
	var counters map[string]int64
	err := c.call(http.MethodGet, "/bittorrent", stateWait, &counters)
	if err != nil {
		return nil, err
	}
	return counters, nil
}

// Subscriptions returns what the backend knows of each subscription.
func (c Client) Subscriptions() ([]SubscriptionState, error) {
	var states []SubscriptionState
	err := c.call(http.MethodGet, "/subscriptions", stateWait, &states)
	return states, err
}

// StartSubscriptionUpdate makes the backend start a download of the list of a subscription now
// (of all of them with no name) and returns the states at once; Subscriptions tells how it
// goes, the attempted time of the subscription is new once it has ended.
func (c Client) StartSubscriptionUpdate(name string) ([]SubscriptionState, error) {
	var states []SubscriptionState
	err := c.call(http.MethodPost, "/subscriptions/update?wait=0&name="+url.QueryEscape(name), startWait+stateWait, &states)
	return states, err
}

// UpdateSubscriptions makes the backend download the list of a subscription now (all of
// them with no name) and returns what it knows of them then.
func (c Client) UpdateSubscriptions(name string) ([]SubscriptionState, error) {
	var states []SubscriptionState
	err := c.call(http.MethodPost, "/subscriptions/update?name="+url.QueryEscape(name), updateWait, &states)
	return states, err
}

// LoadSubscription makes the backend download a list from an address, asked with the request,
// to be shown.
func (c Client) LoadSubscription(address string, request ListRequest, timeout time.Duration) (*SubscriptionPreview, error) {
	preview := new(SubscriptionPreview)
	err := c.send(http.MethodPost, "/subscriptions/load", timeout, loadAsked{Address: address, ListRequest: request}, preview)
	if err != nil {
		return nil, err
	}
	return preview, nil
}

// StartLoad makes the backend start a download of a list from an address, asked with the
// request, to be shown.
func (c Client) StartLoad(address string, request ListRequest) (*LoadJob, error) {
	job := new(LoadJob)
	err := c.send(http.MethodPost, "/subscriptions/load/start", stateWait, loadAsked{Address: address, ListRequest: request}, job)
	if err != nil {
		return nil, err
	}
	return job, nil
}

// LoadState asks the backend how a download of a list for the page goes.
func (c Client) LoadState(id string) (*LoadJob, error) {
	job := new(LoadJob)
	err := c.call(http.MethodGet, "/subscriptions/load/state?id="+url.QueryEscape(id), stateWait, job)
	if err != nil {
		return nil, err
	}
	return job, nil
}

// CancelLoad makes the backend stop a download of a list for the page.
func (c Client) CancelLoad(id string) (*LoadJob, error) {
	job := new(LoadJob)
	err := c.call(http.MethodPost, "/subscriptions/load/cancel?id="+url.QueryEscape(id), stateWait, job)
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
