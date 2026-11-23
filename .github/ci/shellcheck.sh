#!/bin/sh
# .github/ci/shellcheck.sh: ShellCheck of every shell script of the repository at severity warning, from the
# root of the repository in koalaman/shellcheck-alpine (.github/workflows/shellcheck.yml).
# What runs on OpenWrt is read as busybox's sh (`local` is there): the files of the packages that
# start with #!/bin/sh or end in .sh, install.sh, and the preinst/postinst/prerm/postrm of the
# packages' Makefiles; every other *.sh as its shebang says. A finding fails unless
# .github/ci/shellcheck.baseline lists it (file, severity, message and code, without line and
# column: an edit elsewhere in the file keeps it); a listed finding no longer made fails too, so
# the list only shrinks. Findings are told as GitHub annotations.
set -eu
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# the scripts of the packages' Makefiles, $$ of make as $; at a fixed place for stable names
mk=/tmp/makefile-scripts
rm -rf "$mk" && mkdir -p "$mk"
for makefile in podkop/Makefile luci-app-podkop/Makefile; do
	awk -v out="$mk/${makefile%/Makefile}" '
		/^define Package\/[^\/]+\/(preinst|postinst|prerm|postrm)$/ { split($2, p, "/"); name = out "." p[2] "." p[3]; next }
		/^endef$/ { name = ""; next }
		name != "" { gsub(/\$\$/, "$"); print > name }' "$makefile"
done

find podkop/files luci-app-podkop/root -type f | while read -r f; do
	case $f in
	*.sh) echo "$f" ;;
	*) case $(head -n 1 "$f") in '#!'*/sh | '#!'*/sh\ *) echo "$f" ;; esac ;;
	esac
done > "$tmp/openwrt"
{ echo install.sh; find "$mk" -type f; } >> "$tmp/openwrt"
find . \( -path ./.git -o -name node_modules -o -path ./podkop/files -o -path ./luci-app-podkop/root \) -prune \
	-o -type f -name '*.sh' ! -path ./install.sh -print | sed 's|^\./||' > "$tmp/other"
sort -o "$tmp/openwrt" "$tmp/openwrt"
sort -o "$tmp/other" "$tmp/other"

check() { # LIST [OPTION...]
	list=$1
	shift
	rc=0
	# shellcheck disable=SC2046 # one word for each file (no spaces in the names)
	shellcheck -S warning -f gcc "$@" $(cat "$list") >> "$tmp/found" || rc=$?
	# 1: findings; above: a file not read, bad options
	[ "$rc" -le 1 ] || { echo "::error::shellcheck failed with status $rc"; exit 1; }
}
: > "$tmp/found"
check "$tmp/openwrt" -s busybox
check "$tmp/other"
echo "as busybox's sh: $(tr '\n' ' ' < "$tmp/openwrt")"
echo "as their shebang: $(tr '\n' ' ' < "$tmp/other")"

grep -v -e '^#' -e '^$' .github/ci/shellcheck.baseline > "$tmp/baseline" || true
awk -v baseline="$tmp/baseline" '
	BEGIN { while ((getline line < baseline) > 0) known[line] = 1 }
	{
		rest = $0
		file = substr(rest, 1, index(rest, ":") - 1); rest = substr(rest, index(rest, ":") + 1)
		row = substr(rest, 1, index(rest, ":") - 1); rest = substr(rest, index(rest, ":") + 1)
		col = substr(rest, 1, index(rest, ":") - 1); rest = substr(rest, index(rest, ":") + 2)
		seen[file ": " rest] = 1
		if (file ": " rest in known) {
			listed++
		} else {
			printf "::error file=%s,line=%s,col=%s::%s\n", file, row, col, rest
			bad++
		}
	}
	END {
		for (k in known) if (!(k in seen)) {
			printf "::error::no longer found, take it out of .github/ci/shellcheck.baseline: %s\n", k
			bad++
		}
		printf "%d findings of the baseline, %d failures\n", listed, bad
		exit (bad > 0 ? 1 : 0)
	}' "$tmp/found"
