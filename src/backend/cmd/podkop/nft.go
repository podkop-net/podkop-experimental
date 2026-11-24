//go:build lab && linux

package main

import (
	"bufio"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/podkop-net/podkop-experimental/src/backend/firewall"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/spf13/cobra"
)

// The nftables table of the backend by hand: the commands exist to time the netlink way
// against the nft program on a router and to look at what the backend would make.
var commandNft = &cobra.Command{
	Use:   "nft",
	Short: "The firewall table over netlink, by hand",
}

var (
	commandNftFlagInterfaces []string
	commandNftFlagExcludeNTP bool
	commandNftFlagFile       string
	commandNftFlagFrom       string
	commandNftFlagLot        int
)

func init() {
	apply := &cobra.Command{
		Use:   "apply",
		Short: "Make the table anew",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			started := time.Now()
			err := firewall.Apply(&firewall.Plan{Intent: dataplane.Intent{Interfaces: commandNftFlagInterfaces, ExcludeNTP: commandNftFlagExcludeNTP}})
			nftDone(err, "table "+dataplane.FirewallTable+" applied", started)
		},
	}
	apply.Flags().StringArrayVar(&commandNftFlagInterfaces, "interface", nil, "An interface traffic is taken from (may be repeated)")
	apply.Flags().BoolVar(&commandNftFlagExcludeNTP, "exclude-ntp", false, "Leave UDP port 123 alone")
	fill := &cobra.Command{
		Use:   "fill",
		Short: "Make the set of subnets hold the addresses and prefixes of a file, one a line",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			started := time.Now()
			prefixes, err := nftRead(commandNftFlagFile)
			var ranges int
			if err == nil {
				ranges, err = firewall.ReplaceSet(firewall.SetSubnets, prefixes, commandNftFlagLot)
			}
			nftDone(err, strconv.Itoa(len(prefixes))+" prefixes, "+strconv.Itoa(ranges)+" ranges in the set", started)
		},
	}
	fill.Flags().StringVar(&commandNftFlagFile, "file", "", "The list")
	fill.Flags().IntVar(&commandNftFlagLot, "lot", 0, "Ranges a transaction (0: the whole set in one)")
	update := &cobra.Command{
		Use:   "update",
		Short: "Bring the set of subnets from the list it was filled with to another by what differs, as the backend does",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			started := time.Now()
			previous, err := nftRead(commandNftFlagFrom)
			var next []firewall.Range
			if err == nil {
				next, err = nftRead(commandNftFlagFile)
			}
			if err == nil {
				err = firewall.Update(&firewall.Plan{Intent: dataplane.Intent{Interfaces: commandNftFlagInterfaces}, Subnets: previous}, &firewall.Plan{Intent: dataplane.Intent{Interfaces: commandNftFlagInterfaces}, Subnets: next})
			}
			nftDone(err, strconv.Itoa(len(previous))+" prefixes before, "+strconv.Itoa(len(next))+" after", started)
		},
	}
	update.Flags().StringVar(&commandNftFlagFrom, "from", "", "The list the set was filled with")
	update.Flags().StringVar(&commandNftFlagFile, "file", "", "The list it is to hold")
	update.Flags().StringArrayVar(&commandNftFlagInterfaces, "interface", nil, "The interfaces the table was made with")
	remove := &cobra.Command{
		Use:   "remove",
		Short: "Delete the table",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			nftDone(firewall.Remove(), "table "+dataplane.FirewallTable+" removed", time.Now())
		},
	}
	commandNft.AddCommand(apply, fill, update, remove)
	mainCommand.AddCommand(commandNft)
}

// nftRead reads addresses and prefixes, one a line; what is neither is left out, as
// the shell backend leaves it out.
func nftRead(path string) ([]firewall.Range, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var ranges []firewall.Range
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			address, addressErr := netip.ParseAddr(line)
			if addressErr != nil {
				continue
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		if item, ok := firewall.RangeOf(prefix); ok {
			ranges = append(ranges, item)
		}
	}
	return ranges, scanner.Err()
}

func nftDone(err error, what string, started time.Time) {
	if err != nil {
		os.Stderr.WriteString("error: " + E.Cause(err, "nft").Error() + "\n")
		os.Exit(1)
	}
	os.Stdout.WriteString(what + "; " + strconv.FormatInt(time.Since(started).Milliseconds(), 10) + " ms; most memory held " + peakMemory() + "\n")
}

// peakMemory is the high-water mark of this process's resident memory, as the
// kernel counts it.
func peakMemory() string {
	content, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return "unknown"
	}
	for _, line := range strings.Split(string(content), "\n") {
		if value, found := strings.CutPrefix(line, "VmHWM:"); found {
			return strings.TrimSpace(value)
		}
	}
	return "unknown"
}
