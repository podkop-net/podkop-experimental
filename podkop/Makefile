include $(TOPDIR)/rules.mk

PKG_NAME:=podkop-exp

PKG_VERSION := $(if $(PODKOP_VERSION),$(PODKOP_VERSION),0.$(shell date +%d%m%Y))

PKG_RELEASE:=1

PKG_MAINTAINER:=ITDog <podkop@itdog.info>
# the backend is GPL-2.0-or-later; the binary links sing-box (podkop-engine), which is
# GPL-3.0-or-later
PKG_LICENSE:=GPL-2.0-or-later GPL-3.0-or-later

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_BUILD_FLAGS:=no-mips16

# The backend, src/backend of this repository: next to this directory in a checkout, or
# copied into it (src/backend) where the package is built alone.
BACKEND_DIR:=$(firstword $(wildcard $(CURDIR)/src/backend $(CURDIR)/../src/backend))

GO_PKG:=github.com/podkop-net/podkop-experimental/src/backend
GO_PKG_BUILD_PKG:=$(GO_PKG)/cmd/podkop
# the tags podkop-engine is built with; the commands of the lab (tag lab) are not in the
# package
GO_PKG_TAGS:=with_quic,with_utls,with_clash_api,podkop_slim,badlinkname,tfogo_checklinkname0
GO_PKG_LDFLAGS:=-checklinkname=0
# the version of podkop the page shows, and the one of sing-box: the version of sing-box
# go.mod requires, and the commit of podkop-engine it is replaced with
ENGINE_BASE:=$(shell sed -n 's|^require github.com/sagernet/sing-box v||p;s|^[[:space:]]*github.com/sagernet/sing-box v\([^ ]*\)$$|\1|p' $(BACKEND_DIR)/go.mod | head -n 1)
ENGINE_COMMIT:=$(shell sed -n 's|^replace github.com/sagernet/sing-box => .*-\([0-9a-f]\{12\}\)$$|\1|p' $(BACKEND_DIR)/go.mod)
# the release of podkop-engine that commit is (podkop-net/podkop-engine): changed with the
# replace of go.mod (and the comment above it; a test of the backend holds the two together)
ENGINE_RELEASE:=r20
GO_PKG_LDFLAGS_X:=$(GO_PKG).Version=$(PKG_VERSION) \
	$(GO_PKG).EngineRelease=$(ENGINE_RELEASE) \
	github.com/sagernet/sing-box/constant.Version=$(ENGINE_BASE)-pdk-$(ENGINE_COMMIT)

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Package/podkop-exp
	SECTION:=net
	CATEGORY:=Network
	TITLE:=Domain routing app, the backend in Go (experimental)
	URL:=https://podkop.net
	DEPENDS:=$(GO_ARCH_DEPENDS) +ca-bundle +kmod-nft-tproxy
	# podkop is the package of itdoginfo/podkop: the same service, settings and files.
	# https-dns-proxy, nextdns and luci-app-xray take the forwarding of dnsmasq as soon as
	# they are installed. podkop-engine is the sing-box of podkop 0.7 and nothing else.
	# A sing-box package does not conflict: this package has no /usr/bin/sing-box and
	# touches neither the settings nor the files of one. opkg alone reads these names
	# (apk packages of OpenWrt have no conflicts): the backend tells what took dnsmasq or
	# the marks over at run time (podkop global_check).
	CONFLICTS:=podkop https-dns-proxy nextdns luci-app-xray podkop-engine podkop-engine-full
endef

define Package/podkop-exp/description
	Domain routing. Use of VLESS, Shadowsocks technologies.
	One program: the backend of podkop with sing-box (podkop-engine) inside it, as a
	library. It is not a sing-box for other programs: a sing-box package may be installed
	beside it.
endef

define Package/podkop-exp/conffiles
/etc/config/podkop
endef

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) $(BACKEND_DIR)/. $(PKG_BUILD_DIR)/
endef

# An upgrade made by apk does not stop the service (the script of the removal is not run,
# and a start of a service that runs changes nothing): the backend that runs would stay the
# one of the package that was replaced, so a service that runs is restarted. opkg has
# stopped it before the upgrade: it is started (a restart would first stop what procd no
# longer has, and ubus says "Command failed: Not found"). The guard is new: on an upgrade
# from podkop 0.7 nothing would enable it (only a fresh install enables services), so it is
# enabled here unless the settings turn it off.
define Package/podkop-exp/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
# start what is stopped, restart what runs
again() { if "$$1" running; then "$$1" restart; else "$$1" start; fi; }
if [ "$${PKG_UPGRADE}" = "1" ]; then
	case "$$(uci -q get podkop.settings.guard)" in
	0 | off | false | no | disabled) ;;
	*) /etc/init.d/podkop-guard enable; again /etc/init.d/podkop-guard ;;
	esac
	again /etc/init.d/podkop
fi
exit 0
endef

# The services are stopped by the prerm OpenWrt gives every package (default_prerm), and
# the stop of podkop gives back the DNS of the LAN, the firewall table and the routing; a
# stop of its own here would stop them twice ("Command failed: Not found").
# The copy of the dashboard YACD that sing-box serves (src/backend/yacd) goes with the
# package; an upgrade keeps it. So do the files of the NTP hook (files/etc/hotplug.d/ntp,
# src/backend/clock), the hook itself going with the package. The lists of the
# subscriptions hold the credentials of their servers: they go with the package too, the
# identifier of the router (/etc/podkop/hwid) stays. opkg runs the old prerm at an upgrade
# too, with PKG_UPGRADE=1 ($1 is not "upgrade": default_prerm sources the script, $1 is its
# path); apk runs none.
define Package/podkop-exp/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
grep -q "105 podkop" /etc/iproute2/rt_tables 2> /dev/null && sed -i "/105 podkop/d" /etc/iproute2/rt_tables
[ "$${PKG_UPGRADE}" = 1 ] || rm -rf /usr/share/podkop/ui /usr/share/podkop/ui.new /usr/share/podkop/ui.old /usr/share/podkop/ui.builtin
[ "$${PKG_UPGRADE}" = 1 ] || rm -f /var/state/podkop-ntp /var/state/podkop-ntp-synced /etc/podkop-time
[ "$${PKG_UPGRADE}" = 1 ] || rm -rf /usr/share/podkop/subscriptions
exit 0
endef

define Package/podkop-exp/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(GO_PKG_BUILD_BIN_DIR)/podkop $(1)/usr/bin/podkop

	$(INSTALL_DIR) $(1)/usr/share/podkop
	$(CP) ./files/usr/share/podkop/yacd $(1)/usr/share/podkop/
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/podkop $(1)/etc/config/podkop
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/podkop $(1)/etc/init.d/podkop
	$(INSTALL_BIN) ./files/etc/init.d/podkop-guard $(1)/etc/init.d/podkop-guard
	$(INSTALL_DIR) $(1)/usr/libexec/podkop
	$(INSTALL_BIN) ./files/usr/libexec/podkop/guard $(1)/usr/libexec/podkop/guard
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/etc/uci-defaults/99-podkop $(1)/etc/uci-defaults/99-podkop
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_DATA) ./files/etc/hotplug.d/iface/50-podkop $(1)/etc/hotplug.d/iface/50-podkop
	$(INSTALL_DIR) $(1)/etc/hotplug.d/ntp
	$(INSTALL_DATA) ./files/etc/hotplug.d/ntp/60-podkop $(1)/etc/hotplug.d/ntp/60-podkop
	$(INSTALL_DIR) $(1)/lib/upgrade
	$(INSTALL_DATA) ./files/lib/upgrade/podkop.sh $(1)/lib/upgrade/podkop.sh
	# the identifier of a router whose hardware has none, made once (x-hwid of subscriptions)
	$(INSTALL_DIR) $(1)/lib/upgrade/keep.d
	$(INSTALL_DATA) ./files/lib/upgrade/keep.d/podkop-exp $(1)/lib/upgrade/keep.d/podkop-exp
endef

$(eval $(call BuildPackage,podkop-exp))
