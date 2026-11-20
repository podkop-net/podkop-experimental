package subscription

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// router makes a root of a test: files by path, and symbolic links (target after "->").
func router(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for path, content := range files {
		full := filepath.Join(root, path)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		if target, isLink := cutLink(content); isLink {
			require.NoError(t, os.Symlink(filepath.Join(root, target), full))
			continue
		}
		require.NoError(t, os.WriteFile(full, []byte(content), 0o644))
	}
	return root
}

func cutLink(content string) (string, bool) {
	if len(content) > 3 && content[:3] == "-> " {
		return content[3:], true
	}
	return "", false
}

// an Ethernet interface of the board: its device, type and address
func ethernet(files map[string]string, name string, device string, address string, assigned string) {
	files["sys/devices/"+device+"/net/"+name+"/x"] = ""
	files["sys/class/net/"+name+"/device"] = "-> sys/devices/" + device
	files["sys/class/net/"+name+"/type"] = "1\n"
	files["sys/class/net/"+name+"/address"] = address + "\n"
	files["sys/class/net/"+name+"/addr_assign_type"] = assigned + "\n"
}

func base() map[string]string {
	return map[string]string{
		"tmp/sysinfo/board_name": "xiaomi,mi-router-ax3000t\n",
		"tmp/sysinfo/model":      "Xiaomi Mi Router AX3000T\n",
		"etc/openwrt_release":    "DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='24.10.4'\n",
	}
}

func TestDeviceLabelAddressFromTheDeviceTree(t *testing.T) {
	t.Parallel()
	files := base()
	files["proc/device-tree/aliases/label-mac-device"] = "/soc/ethernet@15100000/mac@0\x00"
	files["proc/device-tree/soc/ethernet@15100000/mac@0/mac-address"] = "\x24\xcf\x24\x11\x22\x33"
	// the address the user set on the WAN does not count
	ethernet(files, "eth0", "platform/15100000.ethernet", "aa:bb:cc:00:00:01", "3")
	device := ReadDevice(router(t, files))
	require.Equal(t, "label-mac", device.Source)
	require.Equal(t, "24:cf:24:11:22:33", device.Value)
	require.Len(t, device.HWID, 32)
	require.Regexp(t, `^[a-zA-Z0-9=-]{10,64}$`, device.HWID)
	require.Equal(t, "Xiaomi Mi Router AX3000T", device.Model)
	require.Equal(t, "24.10.4", device.Release)
	header := device.Headers("0.8.5", Custom{})
	require.Equal(t, "podkop/0.8.5", header.Get("User-Agent"))
	require.Equal(t, device.HWID, header.Get("x-hwid"))
	require.Equal(t, "OpenWrt", header.Get("x-device-os"))
	require.Equal(t, "24.10.4", header.Get("x-ver-os"))
	require.Equal(t, "Xiaomi Mi Router AX3000T", header.Get("x-device-model"))
}

// The label device has its address in another place of the flash (nvmem): its interface
// came with it, unless it was changed since.
func TestDeviceLabelAddressOfTheInterface(t *testing.T) {
	t.Parallel()
	files := base()
	files["proc/device-tree/aliases/label-mac-device"] = "/soc/ethernet@15100000/mac@0\x00"
	files["sys/firmware/devicetree/base/soc/ethernet@15100000/mac@0/compatible"] = "x"
	ethernet(files, "eth0", "platform/15100000.ethernet", "24:cf:24:11:22:33", "0")
	files["sys/class/net/eth0/of_node"] = "-> sys/firmware/devicetree/base/soc/ethernet@15100000/mac@0"
	device := ReadDevice(router(t, files))
	require.Equal(t, "label-mac", device.Source)
	require.Equal(t, "24:cf:24:11:22:33", device.Value)

	// changed by the settings: the label of board.json then
	files["sys/class/net/eth0/addr_assign_type"] = "3\n"
	files["etc/board.json"] = `{"model":{"id":"x"},"system":{"label_macaddr":"24:CF:24:11:22:33"}}`
	device = ReadDevice(router(t, files))
	require.Equal(t, "label-mac", device.Source)
	require.Equal(t, "24:cf:24:11:22:33", device.Value)
}

func TestDeviceOtherSources(t *testing.T) {
	t.Parallel()
	// x86: the UUID of the machine; the placeholder of a firmware is none
	files := base()
	files["sys/class/dmi/id/product_uuid"] = "03000200-0400-0500-0006-000700080009\n"
	ethernet(files, "eth0", "pci0000:00/0000:00:03.0", "52:54:00:12:34:56", "0")
	device := ReadDevice(router(t, files))
	require.Equal(t, "ethernet", device.Source)
	require.Equal(t, "52:54:00:12:34:56", device.Value)
	files["sys/class/dmi/id/product_uuid"] = "6F1C9A0E-3B52-4C1E-9A55-2D4A1B0F7C11\n"
	device = ReadDevice(router(t, files))
	require.Equal(t, "dmi-uuid", device.Source)
	require.Equal(t, "6f1c9a0e-3b52-4c1e-9a55-2d4a1b0f7c11", device.Value)

	// a Raspberry Pi: the serial of /proc/cpuinfo
	files = base()
	files["proc/cpuinfo"] = "processor\t: 0\nHardware\t: BCM2835\nSerial\t\t: 10000000abcdef01\n"
	device = ReadDevice(router(t, files))
	require.Equal(t, "serial", device.Source)
	require.Equal(t, "10000000abcdef01", device.Value)

	// a USB adapter and a random address do not count; the Wi-Fi radio does
	files = base()
	ethernet(files, "eth1", "platform/usb1/1-1/1-1:1.0", "00:e0:4c:68:00:01", "0")
	ethernet(files, "eth0", "platform/1e100000.ethernet", "0a:1b:2c:3d:4e:5f", "1")
	files["sys/class/ieee80211/phy0/macaddress"] = "24:cf:24:aa:bb:cc\n"
	device = ReadDevice(router(t, files))
	require.Equal(t, "wifi", device.Source)
	require.Equal(t, "24:cf:24:aa:bb:cc", device.Value)
}

// Nothing of the hardware: a random identifier, made once and kept.
func TestDeviceRandomIsKept(t *testing.T) {
	t.Parallel()
	root := router(t, base())
	first := ReadDevice(root)
	require.Equal(t, "random", first.Source)
	second := ReadDevice(root)
	require.Equal(t, first.HWID, second.HWID)
	content, err := os.ReadFile(filepath.Join(root, "etc/podkop/hwid"))
	require.NoError(t, err)
	require.Contains(t, string(content), first.Value)
}

// The same hardware is the same identifier; another board with the same address is not.
func TestDeviceIdentifierIsStable(t *testing.T) {
	t.Parallel()
	files := base()
	files["etc/board.json"] = `{"system":{"label_macaddr":"24:cf:24:11:22:33"}}`
	first := ReadDevice(router(t, files)).HWID
	require.Equal(t, first, ReadDevice(router(t, files)).HWID)
	files["tmp/sysinfo/board_name"] = "other,board\n"
	require.NotEqual(t, first, ReadDevice(router(t, files)).HWID)
}
