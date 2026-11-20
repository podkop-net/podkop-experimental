package subscription

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Device is the router as a provider is told of it: the panels of providers (Remnawave)
// count the devices of a subscription by an identifier the client sends, and some send
// only placeholders to a client without one.
type Device struct {
	// HWID is the identifier: a hash of what the hardware is, the same after a new
	// firmware, a reset of the settings and a change of the address of an interface.
	HWID string
	// Source tells what it was made of (label-mac, dmi-uuid, serial, ethernet, wifi,
	// random); Value is that.
	Source string
	Value  string
	// Model and Release are the model of the router and the release of OpenWrt.
	Model   string
	Release string
}

// HWIDVariable, set in the environment, is the identifier sent in place of the one of the
// hardware: for a test bench, whose devices are not to take places in a subscription.
const HWIDVariable = "PODKOP_HWID"

// hwidVersion is in what the identifier is made of: it may never change, or every router
// becomes a new device of its subscriptions.
const hwidVersion = "podkop-hwid-v1"

// ReadDevice finds out what the router is. Root is "/" but in a test. The identifier is made
// of the first of these the router has:
//
//  1. the address on its label: the device of the alias label-mac-device of the device
//     tree, its address there or the one its interface came with, or what OpenWrt read of
//     the flash for it (system.label_macaddr of /etc/board.json), as get_mac_label of
//     /lib/functions/system.sh does;
//  2. the UUID of the machine (DMI), on x86 and in a virtual machine;
//  3. the serial number of the board (the device tree, /proc/cpuinfo);
//  4. the address the first built-in Ethernet interface came with;
//  5. the address of the first Wi-Fi radio;
//  6. a random one, made once and kept in /etc/podkop/hwid.
//
// An address set in the settings (a clone of a MAC for the ISP) is never taken: two routers
// may have the same, and a change of it would make a new device.
func ReadDevice(root string) Device {
	read := func(path string) string {
		content, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			return ""
		}
		return strings.TrimSpace(strings.TrimRight(string(content), "\x00"))
	}
	device := Device{Model: read("tmp/sysinfo/model"), Release: release(read("etc/openwrt_release"))}
	board := read("tmp/sysinfo/board_name")
	device.Source, device.Value = hardwareID(root, read)
	if device.Source == "" {
		device.Source, device.Value = "random", randomID(filepath.Join(root, "etc/podkop/hwid"))
	}
	sum := sha256.Sum256([]byte(hwidVersion + "|" + board + "|" + device.Source + "|" + device.Value))
	device.HWID = hex.EncodeToString(sum[:16])
	if forced := os.Getenv(HWIDVariable); forced != "" {
		device.HWID, device.Source = forced, "environment"
	}
	return device
}

func hardwareID(root string, read func(string) string) (source string, value string) {
	if address := labelAddress(root, read); address != "" {
		return "label-mac", address
	}
	if uuid := strings.ToLower(read("sys/class/dmi/id/product_uuid")); usableUUID(uuid) {
		return "dmi-uuid", uuid
	}
	if serial := read("proc/device-tree/serial-number"); usableSerial(serial) {
		return "serial", serial
	}
	if serial := cpuSerial(read("proc/cpuinfo")); usableSerial(serial) {
		return "serial", serial
	}
	if address := builtinEthernet(root, read); address != "" {
		return "ethernet", address
	}
	if address := normalAddress(read("sys/class/ieee80211/phy0/macaddress")); address != "" {
		return "wifi", address
	}
	return "", ""
}

// labelAddress is the address on the label of the router.
func labelAddress(root string, read func(string) string) string {
	if node := read("proc/device-tree/aliases/label-mac-device"); strings.HasPrefix(node, "/") {
		for _, property := range []string{"mac-address", "local-mac-address"} {
			content, err := os.ReadFile(filepath.Join(root, "proc/device-tree", node, property))
			if err == nil && len(content) == 6 {
				if address := normalAddress(net.HardwareAddr(content).String()); address != "" {
					return address
				}
			}
		}
		// the address of the device is in another place of the flash (nvmem): its
		// interface came with it
		for _, name := range interfaces(root) {
			target, err := filepath.EvalSymlinks(filepath.Join(root, "sys/class/net", name, "of_node"))
			if err == nil && strings.HasSuffix(target, filepath.Join("devicetree/base", node)) {
				if address := ownAddress(root, read, name); address != "" {
					return address
				}
			}
		}
	}
	var board struct {
		System struct {
			LabelMAC string `json:"label_macaddr"`
		} `json:"system"`
	}
	if json.Unmarshal([]byte(read("etc/board.json")), &board) == nil {
		return normalAddress(board.System.LabelMAC)
	}
	return ""
}

// builtinEthernet is the address the first Ethernet interface of the board came with: an
// interface of a device of the board (not of USB), by name.
func builtinEthernet(root string, read func(string) string) string {
	for _, name := range interfaces(root) {
		if read(filepath.Join("sys/class/net", name, "type")) != "1" {
			continue
		}
		device, err := filepath.EvalSymlinks(filepath.Join(root, "sys/class/net", name, "device"))
		if err != nil || strings.Contains(device, "/usb") {
			continue
		}
		if address := ownAddress(root, read, name); address != "" {
			return address
		}
	}
	return ""
}

// ownAddress is the address of an interface when it is the one it came with
// (addr_assign_type 0: neither random nor set since).
func ownAddress(root string, read func(string) string, name string) string {
	if read(filepath.Join("sys/class/net", name, "addr_assign_type")) != "0" {
		return ""
	}
	return normalAddress(read(filepath.Join("sys/class/net", name, "address")))
}

func interfaces(root string) []string {
	entries, err := os.ReadDir(filepath.Join(root, "sys/class/net"))
	if err != nil {
		return nil
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	slices.Sort(names)
	return names
}

// normalAddress is a MAC address in lower case; none for one that is no address, all zeros,
// a broadcast or a multicast one.
func normalAddress(text string) string {
	address, err := net.ParseMAC(strings.TrimSpace(text))
	if err != nil || len(address) != 6 || address[0]&1 == 1 || bytes.Equal(address, make(net.HardwareAddr, 6)) {
		return ""
	}
	return address.String()
}

// the UUIDs firmwares write for none
var placeholderUUIDs = []string{
	"03000200-0400-0500-0006-000700080009",
	"00020003-0004-0005-0006-000700080009",
	"12345678-1234-5678-90ab-cddeefaabbcc",
}

func usableUUID(uuid string) bool {
	digits := strings.ReplaceAll(uuid, "-", "")
	if len(digits) != 32 || slices.Contains(placeholderUUIDs, uuid) {
		return false
	}
	return strings.Trim(digits, "0") != "" && strings.Trim(digits, "f") != ""
}

func usableSerial(serial string) bool {
	return len(serial) >= 6 && strings.Trim(serial, "0") != "" && !strings.EqualFold(serial, "unknown")
}

// cpuSerial is the line "Serial" of /proc/cpuinfo (Raspberry Pi and other ARM boards).
func cpuSerial(cpuinfo string) string {
	scanner := bufio.NewScanner(strings.NewReader(cpuinfo))
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), ":")
		if found && strings.TrimSpace(key) == "Serial" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// randomID is the identifier of a router that tells nothing of its hardware: made once,
// kept in the file (which the package keeps over an upgrade of the firmware).
func randomID(path string) string {
	if content, err := os.ReadFile(path); err == nil {
		if value := strings.TrimSpace(string(content)); len(value) >= 16 {
			return value
		}
	}
	random := make([]byte, 16)
	_, _ = rand.Read(random)
	value := hex.EncodeToString(random)
	if os.MkdirAll(filepath.Dir(path), 0o755) == nil {
		_ = os.WriteFile(path, []byte(value+"\n"), 0o600)
	}
	return value
}

// release is DISTRIB_RELEASE of /etc/openwrt_release.
func release(content string) string {
	for _, line := range strings.Split(content, "\n") {
		if value, found := strings.CutPrefix(strings.TrimSpace(line), "DISTRIB_RELEASE="); found {
			return strings.Trim(value, `'"`)
		}
	}
	return ""
}

// Headers are what a request for a list says of the client and the device: the name of
// podkop as the client (a provider gives an unknown client the list of links) or the
// User-Agent of the settings, their extra headers, and the headers of the device Remnawave
// reads. The device comes last: no header of the settings takes its place, not even one past
// their checks (ParseCustom), on a router that has no model or release to tell either.
func (d Device) Headers(version string, custom Custom) http.Header {
	header := make(http.Header)
	header.Set("User-Agent", "podkop/"+version)
	header.Set("Accept", "*/*")
	if custom.UserAgent != "" {
		header.Set("User-Agent", custom.UserAgent)
	}
	for _, field := range custom.Headers {
		header.Set(field.Name, field.Value)
	}
	header.Set("x-hwid", d.HWID)
	header.Set("x-device-os", "OpenWrt")
	header.Del("x-ver-os")
	header.Del("x-device-model")
	if release := headerText(d.Release); release != "" {
		header.Set("x-ver-os", release)
	}
	if model := headerText(d.Model); model != "" {
		header.Set("x-device-model", model)
	}
	return header
}

// headerText keeps of a value what a header can carry: printable ASCII.
func headerText(value string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return -1
		}
		return r
	}, value))
}
