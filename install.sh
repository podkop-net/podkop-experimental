#!/bin/sh
# shellcheck shell=dash

# install.sh: podkop-exp from a release of podkop-net/podkop-experimental, the latest one unless
# --release names another.
#   0. the router is checked, and the release is asked of GitHub (or the files of --from are taken)
#   1. what will be done is shown, and the questions are asked before anything is changed: an
#      older release, the packages podkop-exp cannot work beside, the Russian translation
#   2. the packages are downloaded to /tmp and checked against the digests of the release
#   3. kmod-nft-tproxy and kmod-nf-conntrack-netlink are installed from the feeds of OpenWrt
#   4. what podkop-exp cannot work beside is removed
#   5. the flash must hold podkop-exp, compression counted; if it does not, the sing-box packages
#      nothing needs are offered for removal. With nothing to remove at 4 the flash is measured
#      before 3, so that question too comes before any change.
#   6. podkop-exp and its page are installed only when they fit
# Every command shows what it prints, as it prints it (a log of it is kept for the message of a
# failure); one that stays silent is told about every 30 s, with what to check when a server does
# not answer. A failure says what was done to the router already, or that nothing was changed.
# The options: install.sh -h.

REPO=podkop-net/podkop-experimental
D=/tmp/podkop-exp
RAM_MIN_MB=80
# the page, the translation and a margin, KB
RESERVE_KB=1024
# the first release that reads the settings in their format of today (settings.config_version 2)
OLDEST=0.8.8

msg() { printf '\033[32;1m%s\033[0m\n' "$*"; }
note() { printf '\033[33;1m%s\033[0m\n' "$*"; }
red() { printf '\033[31;1m%s\033[0m\n' "$*"; }
# what was done to the router so far, for the message of a failure
CHANGED=
changed() { CHANGED="${CHANGED:+$CHANGED; }$*"; }
die() {
    red "$*"
    if [ -n "$CHANGED" ]; then red "Already done: $CHANGED."; else red "Nothing was changed."; fi
    rm -rf "$D"
    exit 1
}
# bad TEXT: an option that cannot be taken
bad() {
    red "$* (install.sh -h lists the options)"
    exit 2
}
usage() {
    arch="<arch>"
    # shellcheck source=/dev/null
    [ -f /etc/openwrt_release ] && arch=$(. /etc/openwrt_release && echo "$DISTRIB_ARCH" | tr '_' '-')
    cat <<EOF
install.sh [options]: install or upgrade podkop-exp from the releases of $REPO
  -y, --yes          answer yes to the questions: remove the packages podkop-exp cannot work
                     beside, remove the sing-box packages nothing needs when the flash is short,
                     install an older release named by --release. The Russian translation stays
                     as it is: installed if it was, else not (--ru installs it)
  --ru               install the Russian translation of the page, without the question
  --no-ru            do not install it, and do not ask
  --release X.Y.Z    install that release instead of the latest one, an older one too
                     ($OLDEST or newer)
  --from DIR         install the package files in DIR instead of downloading them: from the
                     release page, podkop-exp-<version>-$arch.ipk (.apk on OpenWrt 25.12),
                     luci-app-podkop-exp-<version>..., for Russian luci-i18n-podkop-exp-ru-<version>...
  -h, --help         this help
The answers are read from the input when it is not a terminal (echo y | sh install.sh), else from
the terminal.
EOF
}

# bare VERSION: the numbers of the version of a package or of a tag: v0.8.20-r1, 0.8.20-1 and
# v0.8.20 give 0.8.20
bare() {
    v=${1#v}
    case "$v" in
    *-r[0-9]*) v=${v%-r*} ;;
    *-[0-9]*) v=${v%-*} ;;
    esac
    echo "$v"
}
# vcmp A B: -1, 0 or 1 as the version A is older than B, the same or newer, number by number
vcmp() {
    awk -v a="$1" -v b="$2" 'BEGIN {
        n = split(a, x, "."); m = split(b, y, "."); if (m > n) n = m
        for (i = 1; i <= n; i++) {
            if (x[i] + 0 < y[i] + 0) { print -1; exit }
            if (x[i] + 0 > y[i] + 0) { print 1; exit }
        }
        print 0
    }'
}

YES=0 RU_CHOICE=ask REL='' FROM=''
while [ $# -gt 0 ]; do
    case "$1" in
    -y | --yes) YES=1 ;;
    --no-ru | --no-translation) RU_CHOICE=no ;;
    --ru | --translation) RU_CHOICE=yes ;;
    --release=*) REL=${1#*=} ;;
    --release)
        [ $# -ge 2 ] || bad "--release needs a version: --release 0.8.19"
        REL=$2
        shift
        ;;
    --from=*) FROM=${1#*=} ;;
    --from)
        [ $# -ge 2 ] || bad "--from needs a directory: --from /tmp/pkgs"
        FROM=$2
        shift
        ;;
    -h | --help)
        usage
        exit 0
        ;;
    *) bad "Unknown option: $1" ;;
    esac
    shift
done
if [ -n "$REL" ]; then
    REL=${REL#v}
    echo "$REL" | grep -Eqx '[0-9]+(\.[0-9]+)+' || bad "--release takes a version such as 0.8.19, not $REL"
    [ "$(vcmp "$REL" "$OLDEST")" = -1 ] &&
        bad "podkop-exp before $OLDEST reads another format of the settings: --release takes $OLDEST or newer"
fi
[ -n "$FROM" ] && [ -n "$REL" ] && bad "--from and --release do not go together: the release is that of the files"
[ -z "$FROM" ] || [ -d "$FROM" ] || bad "--from: there is no directory $FROM"
# the work directory is emptied before the files of --from are looked at
if [ -n "$FROM" ]; then
    case "$(cd "$FROM" && pwd -P)/" in "$D"/*) bad "--from cannot take $FROM: install.sh empties its work directory $D first. Put the files in another directory, such as /tmp/pkgs" ;; esac
fi

if command -v apk >/dev/null 2>&1; then
    EXT=apk PM=apk
    installed() { sed -n 's/^P://p' /lib/apk/db/installed; }
    # the version of an installed package: V: in its block of the database
    version_of() { sed -n "/^P:$1\$/,/^\$/s/^V://p" /lib/apk/db/installed; }
    # "<pkg>-<version> is required by:", then the packages
    needed_by() { apk info -r "$1" 2>/dev/null | sed '1d' | grep -v '^$'; }
    update() { apk update; }
    add() { apk add --allow-untrusted "$@"; }
    del() { apk del "$@"; }
else
    EXT=ipk PM=opkg
    installed() { opkg list-installed | awk '{ print $1 }'; }
    # "<pkg> - <version>"
    version_of() { opkg list-installed | awk -v p="$1" '$1 == p { print $3; exit }'; }
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
# can stop it with Ctrl+C). The command runs in the background, so it never reads the input.
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
    run del $1 || die "$1 could not be removed (the output above shows which were)"
    [ -f /etc/config/podkop ] || cp "$D/podkop.config" /etc/config/podkop 2>/dev/null
}

# Where the answers come from: the input when it is not a terminal and the script did not come by
# it (echo y | sh install.sh; with wget -O - URL | sh the input is the rest of the script, and a
# line read there would be lost to the shell); else the terminal, when there is one (sh <(wget
# ...), sh install.sh, wget ... | sh in an SSH session); else none.
ANSWERS=
case "${0##*/}" in
sh | ash | dash | bash | busybox | -sh | -ash | -bash) ;;
*) if [ ! -t 0 ] && { [ -f "$0" ] || [ -p "$0" ]; }; then ANSWERS=input; fi ;;
esac
[ -z "$ANSWERS" ] && (: </dev/tty) 2>/dev/null && ANSWERS=terminal
# read_answer: a line of the answers into $answer; 1 when there is none to read
read_answer() {
    answer=
    case "$ANSWERS" in
    input) read -r answer || [ -n "$answer" ] || return 1 ;;
    terminal) read -r answer </dev/tty || [ -n "$answer" ] || return 1 ;;
    *) return 1 ;;
    esac
    answer=$(printf '%s' "$answer" | tr -d ' \t\r')
    # an answer from the input is not seen otherwise
    [ "$ANSWERS" = input ] && echo "$answer"
    return 0
}
# ask QUESTION [RUSSIAN] [soft]: 0 for yes (y, yes, д, да). -y answers yes to a question that is
# not soft. With no answer to read, a soft question is no, and another one ends the script.
ask() {
    if [ "$YES" = 1 ] && [ "${3:-}" != soft ]; then
        msg "$1 (y/N) y (-y)"
        return 0
    fi
    msg "$1 (y/N)"
    [ -n "${2:-}" ] && msg "$2 (y/N)"
    if ! read_answer; then
        case "$ANSWERS" in
        input) why="the input has ended" todo="give a line (y or n) for each question" ;;
        terminal) why="Ctrl+D on the terminal" todo="run the command again and answer y or n" ;;
        *) why="there is no terminal here" todo="run the command in an SSH session" ;;
        esac
        [ "${3:-}" = soft ] && { note "No answer to read ($why): taken as no"; return 1; }
        die "No answer to read: $why. To install podkop-exp, $todo, or add -y to answer yes"
    fi
    case "$answer" in y | Y | yes | Yes | YES | д | Д | да | Да | ДА) return 0 ;; esac
    return 1
}

# GitHub said no: its API allows 60 requests an hour from an address. uclient-fetch, the wget of
# OpenWrt, prints "HTTP error N"; GNU wget "ERROR N".
QUOTA="GitHub refused the request (HTTP 403 or 429): its API allows 60 requests an hour from one address, and they are likely spent (the subscribers of a mobile operator often share one address). Try again in an hour, or download the packages on a computer and add --from DIR (README: \"Install without GitHub's API\")"
refused() { grep -Eq '(HTTP error|ERROR) (403|429)' "$D/log"; }
# fakeip: a hint for a download that failed while podkop answers for GitHub with an address of its
# FakeIP range: the router's own connection then goes through the rules of podkop
fakeip() {
    for h in api.github.com github.com; do
        if nslookup "$h" 2>/dev/null | awk '/^Address/ && $NF ~ /^198\.1[89]\./ { f = 1 } END { exit !f }'; then
            echo " $h resolves to an address of podkop's FakeIP range (198.18.0.0/15), so the download goes through the rules of podkop: stop podkop (service podkop stop) and run the command again."
            return
        fi
    done
}
# release URL: release.json from the API of GitHub. A failed connection is tried once more after
# 3 s; a refusal of GitHub (403, 429) and a release that is not there (404) are not.
release() {
    for try in 1 2; do
        run wget -O "$D/release.json" "$1" && return 0
        refused && die "$QUOTA"
        if grep -Eq '(HTTP error|ERROR) 404' "$D/log"; then
            [ -n "$REL" ] && die "Release v$REL is not found. The releases: https://github.com/$REPO/releases"
            die "GitHub has no release of $REPO (HTTP 404)"
        fi
        [ "$try" = 2 ] || { note "No answer from GitHub: one more try in 3 s"; sleep 3; }
    done
    die "No answer from api.github.com (the output is above): check the router's internet and DNS (nslookup api.github.com).$(fakeip)"
}
# get NAME: an asset of the release, checked against its digest. With curl, from its download
# address on github.com (curl reads the long header there, and no request of the API is spent);
# else, or when that fails, through the API of GitHub: the wget of OpenWrt (uclient-fetch) cannot
# read a header line longer than 4 KB and waits for its timeout, and github.com answers the
# download address with a header of 9 KB; the answers of api.github.com are short.
get() {
    api=$(jsonfilter -i "$D/release.json" -e "@.assets[@.name=\"$1\"].url")
    url=$(jsonfilter -i "$D/release.json" -e "@.assets[@.name=\"$1\"].browser_download_url")
    sum=$(jsonfilter -i "$D/release.json" -e "@.assets[@.name=\"$1\"].digest")
    # a connection that breaks off (through a proxy, say) is tried again, and a download is taken
    # only when its digest matches
    for try in 1 2 3; do
        of=
        [ "$try" = 1 ] || of=" (try $try of 3)"
        ok=
        if [ -n "$CURL" ]; then
            msg "Downloading $1 with curl from github.com$of..."
            if run curl -fL --connect-timeout 15 -o "$D/$1" "$url"; then ok=1; else note "curl did not get $1 (the output is above): through the API of GitHub next"; fi
        fi
        if [ -z "$ok" ]; then
            msg "Downloading $1 through the API of GitHub$of..."
            if run wget -O "$D/$1" --header='Accept: application/octet-stream' "$api"; then ok=1; else refused && die "$QUOTA"; fi
        fi
        if [ -n "$ok" ]; then
            [ -z "$sum" ] && { note "The release gives no digest of $1 to check it against"; return 0; }
            [ "$sum" = "sha256:$(sha256sum "$D/$1" | cut -d ' ' -f 1)" ] && return 0
            note "$1 does not match its digest (a broken download)"
        fi
        [ "$try" = 3 ] || sleep 3
    done
    die "$1 could not be downloaded (the output is above): check the router's connection to github.com.$(fakeip)"
}
# pick PATTERN: the one file of the directory of --from that matches, in F
pick() {
    F='' n=0
    for x in "$FROM"/$1; do
        [ -f "$x" ] || continue
        F=$x n=$((n + 1))
    done
    [ "$n" -le 1 ] || die "$FROM has $n files $1: leave one of them there"
}
# group WORDS REASON: the packages of FOUND that are among WORDS, on a line with the reason they go
group() {
    g=
    for p in $FOUND; do case " $1 " in *" $p "*) g="$g $p" ;; esac; done
    [ -z "$g" ] || msg " $g: $2"
}
# settings: what becomes of the settings of podkop. podkop-exp converts them once and keeps the
# file as it was, unless the copy of an earlier conversion is there (the format of today, 2, is
# migrate.Version of the backend); COPY is then where the file as it is now is copied first.
settings() {
    COPY=
    [ -f /etc/config/podkop ] || return 0
    if [ "$(uci -q get podkop.settings.config_version)" = 2 ]; then
        msg "Your podkop settings stay: /etc/config/podkop is in the format of podkop-exp already and is kept as it is."
    elif [ -e /etc/config/podkop.pre-0.8.8 ]; then
        COPY=/etc/config/podkop.pre-0.8.8-$(date +%Y%m%d-%H%M%S)
        msg "Your podkop settings stay: podkop-exp converts /etc/config/podkop to its format. /etc/config/podkop.pre-0.8.8 is there from an earlier install, so the file as it is now is copied to $COPY first."
    else
        msg "Your podkop settings stay: podkop-exp converts /etc/config/podkop to its format and keeps them in the old one as /etc/config/podkop.pre-0.8.8."
    fi
}

# room: the flash must hold podkop-exp; the sing-box packages nothing needs are offered for
# removal when it does not (podkop-exp has sing-box inside)
room() {
    FREE=$(free_kb)
    # on opkg the files of an installed podkop-exp are replaced in place
    [ "$EXT" = ipk ] && has podkop-exp && FREE=$((FREE + NEED - RESERVE_KB))
    msg "Flash: podkop-exp needs $((NEED / 1024)) MB, $((FREE / 1024)) MB is free"
    [ "$FREE" -ge "$NEED" ] && return 0
    SHORT="Not enough flash: podkop-exp is not installed. Free $(((NEED - FREE) / 1024 + 1)) MB more and run the command again"
    BOXES=
    for p in $(installed | grep '^sing-box'); do
        others=$(needed_by "$p" | tr '\n' ' ')
        if [ -n "$others" ]; then msg "$p stays: needed by $others"; else BOXES="$BOXES $p"; fi
    done
    BOXES=${BOXES# }
    [ -n "$BOXES" ] || die "$SHORT"
    msg "The flash is short. podkop-exp has sing-box inside and does not use $BOXES; nothing else installed needs it."
    ask "Remove $BOXES to make room for podkop-exp?" "Удалить $BOXES, чтобы освободить место для podkop-exp?" || die "$SHORT"
    remove "$BOXES"
    changed "removed: $BOXES"
    FREE=$(free_kb)
    [ "$FREE" -ge "$NEED" ] || die "Not enough flash even without $BOXES: podkop-exp is not installed. Free $(((NEED - FREE) / 1024 + 1)) MB more and run the command again"
}

# a dropped SSH session does not stop it between the removal and the install
trap '' HUP
rm -rf "$D"
mkdir -p "$D"
[ -f /etc/openwrt_release ] || die "This is not OpenWrt: there is no /etc/openwrt_release"
# shellcheck source=/dev/null
. /etc/openwrt_release
RAM=$(awk '/^MemTotal:/ { print int($2 / 1024) }' /proc/meminfo)
MODEL=$(cat /tmp/sysinfo/model 2>/dev/null)
msg "${MODEL:+$MODEL, }OpenWrt $DISTRIB_RELEASE, $DISTRIB_ARCH, $RAM MB of memory, $FS"
case "$DISTRIB_RELEASE" in 1[0-9].* | 2[0-3].*) die "podkop-exp needs OpenWrt 24.10 or newer (this router: $DISTRIB_RELEASE)" ;; esac
[ "$RAM" -ge "$RAM_MIN_MB" ] || die "podkop-exp needs $RAM_MIN_MB MB of memory or more (this router: $RAM MB)"
[ -n "$DISTRIB_ARCH" ] || die "/etc/openwrt_release names no package architecture"
DASHED=$(echo "$DISTRIB_ARCH" | tr '_' '-')
# the Software page of LuCI or an update holds the lock of the package manager
n=0
while pidof opkg apk >/dev/null && [ $n -lt 60 ]; do
    [ $n = 0 ] && msg "Waiting for another opkg or apk to finish..."
    sleep 2
    n=$((n + 1))
done

# 0. the release: the files of --from, or the answer of GitHub
INST=$(bare "$(version_of podkop-exp)")
if [ -n "$INST" ]; then
    NOWTEXT="Installed now: podkop-exp v$INST."
elif has podkop; then
    NOWTEXT="Installed now: podkop v$(bare "$(version_of podkop)")."
else
    NOWTEXT="podkop-exp is not installed now."
fi
if [ -n "$FROM" ]; then
    pick "podkop-exp-*-$DASHED.$EXT"
    PKGF=$F
    [ -n "$PKGF" ] || die "$FROM has no podkop-exp-<version>-$DASHED.$EXT, the package for this router: take it from https://github.com/$REPO/releases"
    pick "luci-app-podkop-exp-*.$EXT"
    PAGEF=$F
    [ -n "$PAGEF" ] || die "$FROM has no luci-app-podkop-exp-<version>...$EXT, the page: take it from https://github.com/$REPO/releases"
    pick "luci-i18n-podkop-exp-ru*.$EXT"
    RUF=$F
    v=${PKGF##*/podkop-exp-}
    TAG=v$(bare "${v%-"$DASHED".*}")
    SIZE=$(wc -c <"$PKGF")
    WHERE="the files of $FROM"
    note "The files of $FROM are not checked against GitHub's digests: take them from the release page only"
elif [ -n "$REL" ]; then
    TAG=v$REL
else
    msg "Asking GitHub for the latest release of $REPO..."
    release "https://api.github.com/repos/$REPO/releases/latest"
    TAG=$(jsonfilter -i "$D/release.json" -e '@.tag_name')
    [ -n "$TAG" ] || die "The answer of GitHub names no release (the output is above)"
fi
THIS="podkop-exp $TAG"
[ -n "$FROM$REL" ] || THIS="podkop-exp $TAG, the latest release,"

# what podkop-exp cannot work beside: podkop (podkop-exp takes its service, settings and
# files) and its sing-box podkop-engine; what takes the DNS of dnsmasq over
FOUND=$(installed | grep -x -E 'podkop|luci-app-podkop|luci-i18n-podkop-ru|podkop-engine(-full)?|https-dns-proxy|luci-app-https-dns-proxy|luci-i18n-https-dns-proxy-.*|nextdns|luci-app-nextdns|luci-i18n-nextdns-.*|luci-app-xray|luci-i18n-xray-.*' | tr '\n' ' ')
FOUND=${FOUND% }
KMODS=
has kmod-nft-tproxy && has kmod-nf-conntrack-netlink && KMODS=1
CMP=
[ -n "$INST" ] && CMP=$(vcmp "$INST" "${TAG#v}")
# a newer podkop-exp (a test build) is not replaced by the latest release unless it is asked for
if [ "$CMP" = 1 ] && [ -z "$FROM$REL" ]; then
    msg "$NOWTEXT It is newer than the latest release, $TAG: nothing is done. To install $TAG instead, add --release ${TAG#v}."
    rm -rf "$D"
    exit 0
fi
# the same release: nothing to do when its page, the kernel modules and the translation asked for
# are there and nothing podkop-exp cannot work beside is
LEFT=
if [ "$CMP" = 0 ]; then
    [ "$(bare "$(version_of luci-app-podkop-exp)")" = "$INST" ] || LEFT="$LEFT, its page"
    [ -n "$KMODS" ] || LEFT="$LEFT, the kernel modules"
    [ -z "$FOUND" ] || LEFT="$LEFT, the removal of what it cannot work beside"
    [ "$RU_CHOICE" != yes ] || has luci-i18n-podkop-exp-ru || LEFT="$LEFT, the Russian translation"
    if [ -z "$LEFT" ]; then
        msg "$THIS is installed already, with its page and the kernel modules. Nothing to do."
        has luci-i18n-podkop-exp-ru || [ "$RU_CHOICE" = no ] || msg "To add the Russian translation of the page: --ru."
        rm -rf "$D"
        exit 0
    fi
fi
if [ -n "$REL" ]; then
    msg "Asking GitHub for the release v$REL of $REPO..."
    release "https://api.github.com/repos/$REPO/releases/tags/v$REL"
fi
if [ -z "$FROM" ]; then
    NAMES=$(jsonfilter -i "$D/release.json" -e '@.assets[*].name')
    PKG=$(echo "$NAMES" | grep -m 1 "^podkop-exp-.*-$DASHED\.$EXT\$")
    PAGE=$(echo "$NAMES" | grep -m 1 "^luci-app-podkop-exp-.*\.$EXT\$")
    RU=$(echo "$NAMES" | grep -m 1 "^luci-i18n-podkop-exp-ru.*\.$EXT\$")
    [ -n "$PKG" ] && [ -n "$PAGE" ] || die "Release $TAG has no podkop-exp for this router ($DISTRIB_ARCH, .$EXT packages)"
    SIZE=$(jsonfilter -i "$D/release.json" -e "@.assets[@.name=\"$PKG\"].size")
    WHERE="from GitHub"
fi

# 1. what will be done, and the questions
msg "podkop-exp $TAG for $DISTRIB_ARCH ($(((${SIZE:-0} + 524288) / 1048576)) MB, $WHERE) will be installed. $NOWTEXT"
[ -n "$LEFT" ] && msg "It is installed already; left to do:${LEFT#,}."
if [ "$CMP" = 1 ]; then
    msg "$TAG is older than the installed podkop-exp v$INST. An older release does not undo the conversion of your settings, and it ignores the options added after it.$([ -f /etc/config/podkop.pre-0.8.8 ] && echo " The settings as they were before podkop-exp: /etc/config/podkop.pre-0.8.8.")"
    ask "Install the older release $TAG?" || die "$TAG is not installed: podkop-exp v$INST stays."
fi
OLD=
COPY=
if [ -n "$FOUND" ]; then
    msg "These installed packages are removed first: podkop-exp cannot work beside them."
    group "podkop luci-app-podkop luci-i18n-podkop-ru" "podkop-exp takes the place of podkop (the same service, settings and page)"
    group "podkop-engine podkop-engine-full" "the sing-box of podkop 0.7; podkop-exp has sing-box inside"
    DNS=$(echo "$FOUND" | tr ' ' '\n' | grep -E 'https-dns-proxy|nextdns|xray' | tr '\n' ' ')
    case "$DNS" in
    *" "*" "*) group "$DNS" "they take over the DNS forwarding of dnsmasq, which podkop-exp needs" ;;
    *) group "$DNS" "it takes over the DNS forwarding of dnsmasq, which podkop-exp needs" ;;
    esac
    case " $FOUND " in
    *" podkop "*)
        # podkop 0.7 (a shell script) ran the service of its sing-box on this configuration
        [ "$(head -c 2 /usr/bin/podkop 2>/dev/null)" = "#!" ] && OLD=$(uci -q get podkop.settings.config_path)
        [ -n "$OLD" ] && msg "The sing-box service podkop 0.7 ran is switched off, and its configuration $OLD is removed."
        settings
        ask "Remove these packages and install podkop-exp?" "Удалить эти пакеты и поставить podkop-exp? Настройки podkop сохранятся." ||
            die "podkop-exp is not installed: it cannot work while these packages are installed."
        ;;
    *)
        ask "Remove these packages and install podkop-exp?" "Удалить эти пакеты и поставить podkop-exp?" ||
            die "podkop-exp is not installed: it cannot work while these packages are installed."
        ;;
    esac
fi
# the translation of the page: --ru and --no-ru decide; else it is kept where it was (podkop's
# or podkop-exp's), and asked for elsewhere (-y does not answer it)
if [ -n "$FROM" ]; then HAVE_RU=$RUF; else HAVE_RU=$RU; fi
WANT_RU=
if [ "$RU_CHOICE" = no ]; then
    msg "The Russian translation is not installed (--no-ru)"
elif [ -z "$HAVE_RU" ]; then
    if [ -n "$FROM" ]; then
        note "$FROM has no luci-i18n-podkop-exp-ru-<version>.$EXT: the Russian translation is not installed"
    else
        note "Release $TAG has no Russian translation of the page"
    fi
elif [ "$RU_CHOICE" = yes ]; then
    WANT_RU=1
    msg "The Russian translation of the page is installed (--ru)"
elif has luci-i18n-podkop-ru || has luci-i18n-podkop-exp-ru; then
    WANT_RU=1
    msg "The Russian translation of the page is kept: it was installed (--no-ru leaves it out)"
elif [ "$YES" = 1 ]; then
    msg "The Russian translation is not installed (-y does not install it; --ru does)"
elif ask "Русский язык интерфейса ставим? (Install the Russian translation of the page?) (--no-ru / --ru skip this question)" "" soft; then
    WANT_RU=1
fi

# 2. the packages, to /tmp
if [ -z "$FROM" ]; then
    CURL=$(command -v curl)
    get "$PKG"
    PKGF=$D/$PKG
    get "$PAGE"
    PAGEF=$D/$PAGE
    RUF=
    if [ -n "$WANT_RU" ]; then
        get "$RU"
        RUF=$D/$RU
    fi
else
    [ -n "$WANT_RU" ] || RUF=
fi
NEED=$(($(unpacked_kb "$PKGF") * SHARE / 100 + RESERVE_KB))
TOTAL=$(df -kP /overlay / 2>/dev/null | awk 'NR == 2 { print $2 }')
[ "$TOTAL" -ge "$NEED" ] || die "The flash ($((TOTAL / 1024)) MB) is too small for podkop-exp ($((NEED / 1024)) MB)"

# 5 before 3 when nothing is removed: the flash as it is now
[ -n "$FOUND" ] || room

# 3. the kernel modules, asked for by name: a dependency of podkop 0.7 would go with it. A feed
# of the firmware that does not answer is no reason to stop yet.
msg "Updating the package lists ($PM update): the feeds of your firmware, $(grep -c -e '^src' -e '^http' /etc/opkg/distfeeds.conf /etc/apk/repositories.d/distfeeds.list 2>/dev/null | awk -F: '{ n += $NF } END { print n + 0 }') of them..."
LISTS=
run update || {
    LISTS="; the package lists were not updated, the likely cause: check the router's connection to the feeds of OpenWrt (above)"
    note "Some package lists were not updated (the output is above): the kernel modules are looked for in the lists the router has"
}
msg "Installing the kernel modules kmod-nft-tproxy and kmod-nf-conntrack-netlink..."
WAS=
has kmod-nft-tproxy && WAS=1
run add kmod-nft-tproxy || die "kmod-nft-tproxy cannot be installed (kernel $(uname -r); the output is above)$LISTS. podkop-exp needs it for the transparent proxy"
[ -n "$WAS" ] || changed "kmod-nft-tproxy was installed"
WAS=
has kmod-nf-conntrack-netlink && WAS=1
run add kmod-nf-conntrack-netlink || die "kmod-nf-conntrack-netlink cannot be installed (kernel $(uname -r); the output is above)$LISTS. podkop-exp needs it to end the connections of BitTorrent past podkop when the mode changes"
[ -n "$WAS" ] || changed "kmod-nf-conntrack-netlink was installed"

# 4. what podkop-exp cannot work beside, then 5. the flash
if [ -n "$FOUND" ]; then
    if [ -n "$COPY" ]; then
        cp -p /etc/config/podkop "$COPY" || die "/etc/config/podkop could not be copied to $COPY"
        msg "/etc/config/podkop is copied to $COPY"
        changed "/etc/config/podkop was copied to $COPY"
    fi
    remove "$FOUND"
    case " $FOUND " in
    *" podkop "*) changed "removed: $FOUND (your podkop settings stay in /etc/config/podkop; to go back to podkop, install it as its README says)" ;;
    *) changed "removed: $FOUND" ;;
    esac
    if [ -n "$OLD" ]; then
        rm -f "$OLD"
        uci -q set sing-box.main.enabled=0 && uci -q commit sing-box
        msg "The sing-box service of podkop 0.7 is switched off, and $OLD is removed"
        changed "the sing-box service of podkop 0.7 was switched off and $OLD removed"
    fi
    room
fi

# 6. podkop-exp and its page; an older release given by name replaces a newer one
msg "Installing podkop-exp $TAG..."
set -- "$PKGF" "$PAGEF"
[ -n "$RUF" ] && set -- "$@" "$RUF"
[ "$EXT" = ipk ] && [ -n "$FROM$REL" ] && set -- --force-downgrade "$@"
run add "$@" || die "The install failed (the output is above): run install.sh again"
GOT=$(bare "$(version_of podkop-exp)")
[ -n "$GOT" ] || die "podkop-exp is not installed (the output of $PM is above): run install.sh again"
[ "$GOT" = "${TAG#v}" ] || note "$PM kept podkop-exp v$GOT, not $TAG (the output is above)"
rm -rf "$D" /etc/config/podkop-opkg /etc/config/podkop.apk-new
msg "podkop-exp v$GOT is installed. Clear the browser's cache (or use a private window) before opening Services → Podkop."
msg "podkop-exp v$GOT установлен. Перед открытием «Службы → Podkop» очистите кэш браузера (или откройте приватное окно)."
