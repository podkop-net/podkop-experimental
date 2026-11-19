#!/bin/sh
# shellcheck shell=dash

# install.sh: podkop-exp of the latest release of podkop-net/podkop-experimental.
#   1. kmod-nft-tproxy and kmod-nf-conntrack-netlink are installed from the feeds of OpenWrt
#   2. the package of podkop-exp for this router is downloaded from the release
#   3. what podkop-exp cannot work beside is removed, if the user agrees
#   4. the flash must hold podkop-exp, compression counted
#   5. if it does not, the sing-box packages nothing needs are offered for removal
#   6. podkop-exp and its page are installed only when they fit
# Every command shows what it prints, as it prints it (a log of it is kept for the message of a
# failure); one that stays silent is told about every 30 s, with what to check when a server does
# not answer.
#
# Options (after the script: sh <(wget -O - .../install.sh) --no-ru):
#   --no-ru   the Russian translation of the page is not installed (nor asked about)
#   --ru      it is installed without the question
#   -h        this help

REPO=podkop-net/podkop-experimental
D=/tmp/podkop-exp
RAM_MIN_MB=80
# the page, the translation and a margin, KB
RESERVE_KB=1024

msg() { printf '\033[32;1m%s\033[0m\n' "$*"; }
note() { printf '\033[33;1m%s\033[0m\n' "$*"; }
die() {
    printf '\033[31;1m%s\033[0m\n' "$*"
    rm -rf "$D"
    exit 1
}
# ask QUESTION: 0 for yes; anything else, or no input, is no
ask() {
    msg "$1 (y/N)"
    read -r answer || return 1
    case "$answer" in y | Y | yes | Yes | д | Д | да | Да) return 0 ;; esac
    return 1
}

RU_CHOICE=ask
for arg in "$@"; do
    case "$arg" in
    --no-ru | --no-translation) RU_CHOICE=no ;;
    --ru | --translation) RU_CHOICE=yes ;;
    -h | --help)
        echo "install.sh [--no-ru | --ru]: podkop-exp of the latest release"
        echo "  --no-ru   the Russian translation of the page is not installed (nor asked about)"
        echo "  --ru      it is installed without the question"
        exit 0
        ;;
    *) die "Unknown option: $arg (known: --no-ru, --ru, -h)" ;;
    esac
done

if command -v apk >/dev/null 2>&1; then
    EXT=apk PM=apk
    installed() { sed -n 's/^P://p' /lib/apk/db/installed; }
    # "<pkg>-<version> is required by:", then the packages
    needed_by() { apk info -r "$1" 2>/dev/null | sed '1d' | grep -v '^$'; }
    update() { apk update; }
    add() { apk add --allow-untrusted "$@"; }
    del() { apk del "$@"; }
else
    EXT=ipk PM=opkg
    installed() { opkg list-installed | awk '{ print $1 }'; }
    # "What depends on root set", then "<tab><pkg> <version><tab>depends on <name>"
    needed_by() { opkg whatdepends "$1" 2>/dev/null | awk '/depends on/ && $1 != "What" { print $1 }'; }
    update() { opkg update; }
    # shellcheck disable=SC2086
    add() { opkg install $FORCE_SPACE "$@"; }
    del() { opkg remove --force-depends "$@"; }
fi
has() { installed | grep -qx "$1"; }

# ubifs and jffs2 compress: the Go binary of a package takes 40-58% of its size there
# (measured by the install mirror); elsewhere a package takes a little more than its size.
# opkg compares the unpacked size with the free space: on a compressing flash it is told not to.
FS=$(awk '$2 == "/overlay" { o = $3 } $2 == "/" { r = $3 } END { print (o != "" ? o : r) }' /proc/mounts)
case "$FS" in
ubifs | jffs2) SHARE=60 FORCE_SPACE=--force-space ;;
*) SHARE=115 FORCE_SPACE= ;;
esac
# free KB of the flash; ubifs counts its journal as taken until it is written out
free_kb() {
    sync
    df -kP /overlay / 2>/dev/null | awk 'NR == 2 { print $4 }'
}
# the unpacked size of a package file, KB
unpacked_kb() {
    case "$1" in
    *.ipk) bytes=$(tar -xzOf "$1" ./control.tar.gz | tar -xzO ./control | sed -n 's/^Installed-Size: *//p') ;;
    *) bytes=$(apk adbdump "$1" 2>/dev/null | sed -n 's/^ *installed-size: *//p' | head -n 1) ;;
    esac
    [ -n "$bytes" ] || bytes=$(($(wc -c < "$1") * 27 / 10))
    echo $((bytes / 1024))
}
# run COMMAND...: its output is shown as it comes and kept in a log. A command that prints nothing
# for 30 s is told about every 30 s (opkg says "Downloading ..." and then waits for a server that
# may not answer: busybox has no timeout to cut it short, so the user sees what it waits for and
# can stop it with Ctrl+C).
run() {
    rm -f "$D/rc"
    : >"$D/log"
    { "$@" 2>&1; echo $? >"$D/rc"; } | tee "$D/log" &
    pid=$!
    size=0
    quiet=0
    while kill -0 "$pid" 2>/dev/null; do
        sleep 2
        now=$(wc -c <"$D/log" 2>/dev/null || echo 0)
        if [ "$now" = "$size" ]; then quiet=$((quiet + 2)); else size=$now quiet=0; fi
        if [ "$quiet" -gt 0 ] && [ $((quiet % 30)) = 0 ]; then
            note "... still waiting: $quiet s with no output from \"$*\""
            [ "$quiet" = 60 ] && note "    a server does not answer? Check the router's internet and DNS (nslookup downloads.openwrt.org), or press Ctrl+C and try later"
        fi
    done
    wait "$pid" 2>/dev/null
    return "$(cat "$D/rc" 2>/dev/null || echo 1)"
}
# remove PACKAGES: the settings of podkop stay
remove() {
    msg "Removing: $1"
    cp /etc/config/podkop "$D/podkop.config" 2>/dev/null
    # shellcheck disable=SC2086
    run del $1 || die "$1 could not be removed (the output is above)"
    [ -f /etc/config/podkop ] || cp "$D/podkop.config" /etc/config/podkop 2>/dev/null
}
# get NAME: an asset of the release, checked against its digest. Through the API of GitHub first:
# the wget of OpenWrt (uclient-fetch) cannot read a header line longer than 4 KB and waits for
# its timeout, and github.com answers the download address with a header of 9 KB; the answers
# of api.github.com are short. The download address stays for a wget that reads it.
get() {
    api=$(jsonfilter -i "$D/release.json" -e "@.assets[@.name=\"$1\"].url")
    url=$(jsonfilter -i "$D/release.json" -e "@.assets[@.name=\"$1\"].browser_download_url")
    sum=$(jsonfilter -i "$D/release.json" -e "@.assets[@.name=\"$1\"].digest")
    # wget shows its progress; a connection that breaks off (through a proxy, say) is tried again,
    # and a download is taken only when its digest matches
    for try in 1 2 3; do
        if [ "$try" = 1 ]; then msg "Downloading $1..."; else msg "Downloading $1 (try $try of 3)..."; fi
        if run wget -O "$D/$1" --header='Accept: application/octet-stream' "$api" ||
            { note "The API of GitHub did not give $1: the download address next"; run wget -O "$D/$1" "$url"; }; then
            [ -z "$sum" ] && return 0
            [ "$sum" = "sha256:$(sha256sum "$D/$1" | cut -d ' ' -f 1)" ] && return 0
            note "$1 does not match its digest (a broken download)"
        fi
        sleep 3
    done
    die "$1 could not be downloaded (the output is above): check the router's connection to github.com"
}

# a dropped SSH session does not stop it between the removal and the install
trap '' HUP
rm -rf "$D"
mkdir -p "$D"
# shellcheck source=/dev/null
. /etc/openwrt_release
RAM=$(awk '/^MemTotal:/ { print int($2 / 1024) }' /proc/meminfo)
msg "$(cat /tmp/sysinfo/model 2>/dev/null), OpenWrt $DISTRIB_RELEASE, $DISTRIB_ARCH, $RAM MB of memory, $FS"
case "$DISTRIB_RELEASE" in 1[0-9].* | 2[0-3].*) die "podkop-exp needs OpenWrt 24.10 or newer" ;; esac
[ "$RAM" -ge "$RAM_MIN_MB" ] || die "podkop-exp needs $RAM_MIN_MB MB of memory or more"
[ -n "$DISTRIB_ARCH" ] || die "/etc/openwrt_release names no package architecture"
# the Software page of LuCI or an update holds the lock of the package manager
n=0
while pidof opkg apk >/dev/null && [ $n -lt 60 ]; do
    [ $n = 0 ] && msg "Waiting for another opkg or apk to finish..."
    sleep 2
    n=$((n + 1))
done

# 1. the kernel modules, asked for by name: a dependency of podkop 0.7 would go with it. A feed
# of the firmware that does not answer is no reason to stop yet.
msg "Updating the package lists ($PM update): the feeds of your firmware, $(grep -c '^src' /etc/opkg/distfeeds.conf /etc/apk/repositories.d/distfeeds.list 2>/dev/null | awk -F: '{ n += $NF } END { print n + 0 }') of them..."
LISTS=
run update || {
    LISTS="; the package lists were not updated, the likely cause: check the router's connection to the feeds of OpenWrt (above)"
    note "Some package lists were not updated (the output is above): the kernel modules are looked for in the lists the router has"
}
msg "Installing the kernel modules kmod-nft-tproxy and kmod-nf-conntrack-netlink..."
run add kmod-nft-tproxy || die "kmod-nft-tproxy cannot be installed (kernel $(uname -r); the output is above)$LISTS. podkop-exp needs it for the transparent proxy"
run add kmod-nf-conntrack-netlink || die "kmod-nf-conntrack-netlink cannot be installed (kernel $(uname -r); the output is above)$LISTS. podkop-exp needs it to end the connections of BitTorrent past podkop when the mode changes"

# 2. the package for this router
msg "Asking GitHub for the latest release of $REPO..."
run wget -O "$D/release.json" "https://api.github.com/repos/$REPO/releases/latest" ||
    die "GitHub did not answer (the output is above): no connection to api.github.com, or the limit of its API (60 requests an hour) is reached; try again later"
TAG=$(jsonfilter -i "$D/release.json" -e '@.tag_name')
NAMES=$(jsonfilter -i "$D/release.json" -e '@.assets[*].name')
PKG=$(echo "$NAMES" | grep -m 1 "^podkop-exp-.*-$(echo "$DISTRIB_ARCH" | tr '_' '-')\.$EXT\$")
PAGE=$(echo "$NAMES" | grep -m 1 "^luci-app-podkop-exp-.*\.$EXT\$")
RU=$(echo "$NAMES" | grep -m 1 "^luci-i18n-podkop-exp-ru.*\.$EXT\$")
[ -n "$PKG" ] && [ -n "$PAGE" ] || die "Release $TAG has no podkop-exp for $DISTRIB_ARCH"
SIZE=$(jsonfilter -i "$D/release.json" -e "@.assets[@.name=\"$PKG\"].size")
msg "Downloading podkop-exp $TAG for $DISTRIB_ARCH ($((SIZE / 1048576)) MB)..."
get "$PKG"
get "$PAGE"
FILES="$D/$PKG $D/$PAGE"
# the translation of the page: --ru and --no-ru decide; else kept where it was, asked for elsewhere
want_ru() {
    case "$RU_CHOICE" in
    yes) return 0 ;;
    no) return 1 ;;
    esac
    has luci-i18n-podkop-ru || has luci-i18n-podkop-exp-ru || ask "Русский язык интерфейса ставим? (Install the Russian translation of the page?) (--no-ru / --ru skip this question)"
}
[ "$RU_CHOICE" = no ] && msg "The Russian translation is not installed (--no-ru)"
if [ -n "$RU" ] && want_ru; then
    get "$RU"
    FILES="$FILES $D/$RU"
fi
NEED=$(($(unpacked_kb "$D/$PKG") * SHARE / 100 + RESERVE_KB))
TOTAL=$(df -kP /overlay / 2>/dev/null | awk 'NR == 2 { print $2 }')
[ "$TOTAL" -ge "$NEED" ] || die "The flash ($((TOTAL / 1024)) MB) is too small for podkop-exp ($((NEED / 1024)) MB)"

# 3. what podkop-exp cannot work beside: podkop (podkop-exp takes its service, settings and
# files) and its sing-box podkop-engine; what takes the DNS of dnsmasq over
FOUND=$(installed | grep -x -E 'podkop|luci-app-podkop|luci-i18n-podkop-ru|podkop-engine(-full)?|https-dns-proxy|luci-app-https-dns-proxy|luci-i18n-https-dns-proxy-.*|nextdns|luci-app-nextdns|luci-i18n-nextdns-.*|luci-app-xray|luci-i18n-xray-.*' | tr '\n' ' ')
if [ -n "$FOUND" ]; then
    msg "podkop-exp cannot work beside: $FOUND"
    case " $FOUND " in *" podkop "*) msg "The settings of podkop are kept for podkop-exp" ;; esac
    ask "Remove them?" || die "Nothing is changed"
    # podkop 0.7 (a shell script) ran the service of its sing-box on this configuration
    [ "$(head -c 2 /usr/bin/podkop 2>/dev/null)" = "#!" ] && OLD=$(uci -q get podkop.settings.config_path)
    remove "$FOUND"
    if [ -n "${OLD:-}" ]; then
        rm -f "$OLD"
        uci -q set sing-box.main.enabled=0 && uci -q commit sing-box
    fi
fi

# 4. the flash; on opkg the files of an installed podkop-exp are replaced in place
FREE=$(free_kb)
[ "$EXT" = ipk ] && has podkop-exp && FREE=$((FREE + NEED - RESERVE_KB))
msg "Flash: podkop-exp needs $((NEED / 1024)) MB, $((FREE / 1024)) MB is free"

# 5. the sing-box packages nothing needs: podkop-exp has sing-box inside
if [ "$FREE" -lt "$NEED" ]; then
    BOXES=""
    for p in $(installed | grep '^sing-box'); do
        others=$(needed_by "$p" | tr '\n' ' ')
        if [ -n "$others" ]; then msg "$p stays: needed by $others"; else BOXES="$BOXES$p "; fi
    done
    [ -n "$BOXES" ] || die "Not enough flash: free $(((NEED - FREE) / 1024 + 1)) MB more. podkop-exp is not installed."
    msg "podkop-exp does not use $BOXES"
    ask "Remove them to make room?" || die "Not enough flash: podkop-exp is not installed"
    remove "$BOXES"
    FREE=$(free_kb)
    [ "$FREE" -ge "$NEED" ] || die "Not enough flash: free $(((NEED - FREE) / 1024 + 1)) MB more. podkop-exp is not installed."
fi

# 6. podkop-exp and its page
msg "Installing podkop-exp $TAG..."
# shellcheck disable=SC2086
run add $FILES || die "The install failed (the output is above)${FOUND:+; removed: $FOUND, the settings of podkop are kept}: run install.sh again"
rm -rf "$D" /etc/config/podkop-opkg /etc/config/podkop.apk-new
msg "podkop-exp $TAG is installed. Clear the cache of the browser before opening its page in LuCI."
