//go:build lab

package main

// parse-list, a command of the lab: the body of a subscription read as the backend reads it, the
// servers with the outbounds the engine runs, for a stand that runs them against real servers.
// Its output holds the secrets of the servers: a product build leaves it out.

import (
	"context"
	"encoding/json"
	"io"
	"os"

	"github.com/podkop-net/podkop-experimental/src/backend/engine"
	"github.com/podkop-net/podkop-experimental/src/backend/subscription"
	"github.com/sagernet/sing-box/common/sharelink"

	"github.com/spf13/cobra"
)

var commandParseList = &cobra.Command{
	Use:   "parse-list FILE",
	Short: "Read the body of a subscription as the backend does, and print its servers with their outbounds",
	Long: "Read the body of a subscription (a file, or - for the standard input) as the backend reads\n" +
		"the answer of a provider: a list of links, Xray JSON or sing-box JSON. The servers go\n" +
		"through the engine's decoder and the build of sing-box, as a download's do. The output\n" +
		"is JSON: {format, configs, servers: [{name, id, reason, notes, made, outbound}]}, the\n" +
		"outbound tagged with the name of the server. It holds the secrets of the servers.\n\n" +
		"Exit status:\n" +
		"  0  the servers are printed\n" +
		"  2  the body is refused; a line \"error: ...\" on the standard error says why\n" +
		"  1  anything else",
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(parseList(args[0], os.Stdin, os.Stdout, os.Stderr))
	},
}

func init() {
	mainCommand.AddCommand(commandParseList)
}

type parsedServer struct {
	Name     string          `json:"name"`
	ID       string          `json:"id,omitempty"`
	Reason   string          `json:"reason,omitempty"`
	Notes    []string        `json:"notes,omitempty"`
	Made     bool            `json:"made,omitempty"`
	Outbound json.RawMessage `json:"outbound,omitempty"`
}

type parsedList struct {
	Format  string         `json:"format"`
	Configs int            `json:"configs"`
	Servers []parsedServer `json:"servers"`
}

func parseList(path string, input io.Reader, output io.Writer, errorOutput io.Writer) int {
	var body []byte
	var err error
	if path == "-" {
		body, err = io.ReadAll(io.LimitReader(input, subscription.MaxBody+1))
	} else {
		body, err = os.ReadFile(path)
	}
	if err == nil && len(body) > subscription.MaxBody {
		io.WriteString(errorOutput, "error: the body is larger than a list may be\n")
		return 2
	}
	if err != nil {
		io.WriteString(errorOutput, "error: "+sharelink.OneLine(err.Error())+"\n")
		return 1
	}
	list, err := subscription.ParseList(context.Background(), body, subscription.Codec{Decode: engine.DecodeLink, Normalize: engine.NormalizeOutbound})
	if err != nil {
		io.WriteString(errorOutput, "error: "+sharelink.OneLine(err.Error())+"\n")
		return 2
	}
	// built as a download's servers are: those this sing-box cannot build get their reason
	subscription.Check(list.Servers, nil, func(configuration []byte) error {
		_, err := engine.Check(configuration)
		return err
	}, engine.CheckLink)
	parsed := parsedList{Format: list.Format, Configs: list.Configs, Servers: []parsedServer{}}
	for _, server := range list.Servers {
		entry := parsedServer{Name: server.Name, ID: server.ID, Reason: server.Reason, Notes: server.Notes, Made: list.Format != ""}
		if server.ID != "" {
			if content, _, decodeErr := engine.DecodeLink(server.Link); decodeErr == nil {
				var fields map[string]any
				if json.Unmarshal(content, &fields) == nil {
					fields["tag"] = server.Name
					entry.Outbound, _ = json.Marshal(fields)
				}
			}
		}
		parsed.Servers = append(parsed.Servers, entry)
	}
	content, err := json.MarshalIndent(parsed, "", "  ")
	if err != nil {
		io.WriteString(errorOutput, "error: "+err.Error()+"\n")
		return 1
	}
	output.Write(append(content, '\n'))
	return 0
}
