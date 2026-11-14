#!/bin/sh
# A release of podkop is built only on a published podkop-engine state: the commit go.mod
# replaces sing-box with must be SB_1_14_FORK_COMMIT of the podkop-engine tag
# v<sing-box version>-<ENGINE_RELEASE> (a release rN or a pre-release rN-rcM), and go.mod must
# have every replace the go.mod of that fork commit has.
#   sdk/check-engine.sh            run from the root of the repository
# ENGINE_REPO overrides podkop-net/podkop-engine, FORK_REPO podkop-net/sing-box.
set -eu
repo=${ENGINE_REPO:-podkop-net/podkop-engine}
# ENGINE_URL: where the tags are read (a file:// tree for a test)
url=${ENGINE_URL:-https://raw.githubusercontent.com/$repo/refs/tags}
gomod=src/backend/go.mod
mk=podkop/Makefile

commit=$(sed -n 's|^replace github.com/sagernet/sing-box => .*-\([0-9a-f]\{12\}\)$|\1|p' "$gomod")
base=$(sed -n 's|^require github.com/sagernet/sing-box v||p;s|^[[:space:]]*github.com/sagernet/sing-box v\([^ ]*\)$|\1|p' "$gomod" | head -n 1)
release=$(sed -n 's/^ENGINE_RELEASE:=\(r[0-9][0-9]*\(-rc[0-9][0-9]*\)\{0,1\}\)$/\1/p' "$mk")
[ -n "$commit" ] || { echo "go.mod: no replace of sing-box with a pseudo-version" >&2; exit 1; }
[ -n "$base" ] || { echo "go.mod: no require of sing-box" >&2; exit 1; }
[ -n "$release" ] || { echo "$mk: no ENGINE_RELEASE of the form rN or rN-rcM" >&2; exit 1; }

line=$(echo "$base" | cut -d. -f1,2 | tr . _)
tag=v$base-$release
env=$(curl -fsSL --retry 3 "$url/$tag/versions.env") || {
  echo "no tag $tag in $repo: publish the podkop-engine release (or pre-release) first" >&2; exit 1; }
fork=$(printf '%s\n' "$env" | sed -n "s/^SB_${line}_FORK_COMMIT=\([0-9a-f]*\).*/\1/p")
[ -n "$fork" ] || { echo "$tag: versions.env has no SB_${line}_FORK_COMMIT" >&2; exit 1; }
case $fork in
  "$commit"*) echo "go.mod pins $commit = SB_${line}_FORK_COMMIT of $repo $tag" ;;
  *) echo "go.mod pins $commit, but $repo $tag has SB_${line}_FORK_COMMIT=$fork" >&2; exit 1 ;;
esac

# a replace in the go.mod of the fork does not count in a module that requires the fork: go.mod
# has each one of them, the same (the libraries the engine release builds with: quic-go,
# sing-vmess), or the package builds with others than the engine it pins
# FORK_URL: where the go.mod of the fork is read (a file:// tree for a test)
fork_url=${FORK_URL:-https://raw.githubusercontent.com/${FORK_REPO:-podkop-net/sing-box}}
replaces() { sed -n 's/^replace[[:space:]]\{1,\}//p' | sed 's/[[:space:]]\{1,\}/ /g;s/ $//'; }
forkmod=$(curl -fsSL --retry 3 "$fork_url/$fork/go.mod") || {
  echo "no go.mod of the fork at $fork_url/$fork" >&2; exit 1; }
ours=$(replaces < "$gomod")
missing=$(printf '%s\n' "$forkmod" | replaces | while IFS= read -r wanted; do
  printf '%s\n' "$ours" | grep -qxF "$wanted" || echo "  replace $wanted"
done)
[ -z "$missing" ] || {
  printf 'go.mod lacks replaces of the fork %s (its go.mod has them):\n%s\n' "$fork" "$missing" >&2; exit 1; }
echo "go.mod has the $(printf '%s\n' "$forkmod" | replaces | grep -c .) replace(s) of the fork's go.mod"
