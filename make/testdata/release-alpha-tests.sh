#!/usr/bin/env bash
# release-alpha-tests.sh — runs the release templates (release-alpha.mk,
# release-candidate.mk, release.mk and their shared release-common.mk) for real, against a throwaway bare remote, and asserts what reached that remote.
# The alpha cases are go-quicbaas#967:
#
#   1. push.followTags=true (a common global setting) made the release push
#      publish every missing annotated tag reachable from HEAD, not just the one
#      named on the command line — --atomic does not narrow that set.
#   2. A fenced code block quoting "## [X.Y.Z-alpha]" at column one satisfied
#      the CHANGELOG guard, so a release with no real section was cut and pushed.
#
# The public and lockstep cases are automatethethings#173: the version form of
# each release kind, lockstep module tags pushed atomically with the root tag,
# version ordering, the upstream gate (§1a), and the command-line injection
# rules extended to the new inputs. Both kinds of tag are cut on main.
#
# The candidate cases are the owner's 2026-10-07 rulings (release-versioning.md
# §1a): `make release-candidate` cuts vX.Y.Z-rc.N, `make release` (formerly
# release-public) cuts vX.Y.Z, and each target refuses the other kinds.
#
# Nothing here touches the caller's git config or any real remote: HOME and the
# global config are private to each case, and AGENT_GIT is a stub that runs
# plain git (signing is agent-git.sh's contract, not this recipe's).
#
#   bash software/templates/make/testdata/release-alpha-tests.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="$HERE/../release-alpha.mk"
for t in release-alpha.mk release-candidate.mk release.mk release-common.mk; do
	[ -f "$HERE/../$t" ] || { echo "FATAL: no template at $HERE/../$t — the test would measure nothing"; exit 9; }
done

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT
VER=v0.1.0-alpha
HEADING="## [${VER#v}]"
FENCE='```'
LONG_FENCE='````'

ok()  { printf '  PASS  %s\n' "$1"; }
bad() { printf '  FAIL  %s: %s\n' "$1" "$2"; return 1; }

# fixture <case-dir> [lockstep-modules] — a clone of a bare remote on main,
# with the templates included exactly as an adopter includes them. With
# modules, the repo is a Go module with a tracked go.mod in each of them.
# Leaves the caller in the clone.
fixture() {
	local dir="$ROOT/$1" modules="${2:-}" m
	mkdir -p "$dir/home"
	export HOME="$dir/home" GIT_CONFIG_GLOBAL="$dir/home/gitconfig" GIT_CONFIG_NOSYSTEM=1
	git config --global user.name fixture
	git config --global user.email fixture@example.invalid
	git config --global init.defaultBranch main
	git config --global tag.gpgSign false
	git config --global commit.gpgSign false

	git init -q --bare "$dir/remote.git"
	git init -q "$dir/work"
	cd "$dir/work" || exit 9
	git remote add origin "$dir/remote.git"

	printf '#!/bin/sh\nshift\nexec git "$@"\n' > "$dir/agent-git"
	chmod +x "$dir/agent-git"
	cat > Makefile <<EOF
AGENT_GIT ?= $dir/agent-git
REPO_NAME ?= fixture
RELEASE_REMOTE ?= origin
LOCKSTEP_MODULES ?= $modules
include $TEMPLATE
include $HERE/../release.mk
include $HERE/../release-candidate.mk
EOF
	printf '0.0.1-alpha\n' > VERSION
	printf '# Changelog\n' > CHANGELOG.md
	printf 'module github.com/jeremyhahn/fixture\n\ngo 1.24\n' > go.mod
	for m in $modules; do
		mkdir -p "$m"
		printf 'module github.com/jeremyhahn/fixture/%s\n\ngo 1.24\n\nrequire github.com/jeremyhahn/fixture v0.0.1-alpha\n' "$m" > "$m/go.mod"
		git add "$m/go.mod"
	done
	git add Makefile VERSION CHANGELOG.md go.mod
	git commit -q -m initial
	git push -q origin main
}

# changelog <body> — commit a CHANGELOG.md and publish it, so the tree is clean
# and the remote is level with HEAD before the recipe runs.
changelog() {
	printf '# Changelog\n\n%s\n' "$1" > CHANGELOG.md
	git commit -q -am changelog
	git push -q origin main
}

release() { make -s release-alpha VERSION="$VER" >"$ROOT/out" 2>&1; }

remote_tags() { git ls-remote --tags --refs origin | sed 's|.*refs/tags/||' | sort | tr '\n' ' '; }

# expect_released <name> — the recipe succeeded and published exactly one tag.
expect_released() {
	local name="$1"
	if ! release; then bad "$name" "recipe refused: $(tail -n1 "$ROOT/out")"; return 1; fi
	local tags; tags="$(remote_tags)"
	[ "$tags" = "$VER " ] || { bad "$name" "remote tags are [$tags], want only $VER"; return 1; }
	[ "$(git ls-remote origin refs/heads/main | cut -f1)" = "$(git rev-parse HEAD)" ] || { bad "$name" "remote main is not the release commit"; return 1; }
	[ "$(cat VERSION)" = "${VER#v}" ] || { bad "$name" "VERSION is $(cat VERSION)"; return 1; }
	ok "$name"
}

# expect_refused <name> — the CHANGELOG guard stopped the recipe before it
# wrote VERSION, committed, tagged or pushed anything.
expect_refused() {
	local name="$1" head; head="$(git rev-parse HEAD)"
	if release; then bad "$name" "recipe released without a real $HEADING section"; return 1; fi
	grep -q 'CHANGELOG.md has no' "$ROOT/out" || { bad "$name" "refused for the wrong reason: $(tail -n1 "$ROOT/out")"; return 1; }
	[ "$(git rev-parse HEAD)" = "$head" ] || { bad "$name" "a commit was made"; return 1; }
	[ "$(cat VERSION)" = 0.0.1-alpha ] || { bad "$name" "VERSION was written"; return 1; }
	[ -z "$(git status --porcelain)" ] || { bad "$name" "working tree was modified"; return 1; }
	! git rev-parse -q --verify "refs/tags/$VER" >/dev/null || { bad "$name" "a local tag was created"; return 1; }
	[ -z "$(remote_tags)" ] || { bad "$name" "a tag reached the remote"; return 1; }
	ok "$name"
}

# Each case runs in its own subshell (its own HOME, clone and remote) and
# reports through its exit status.
pass=0; fail=0; n=0
tally() { if "$@"; then pass=$((pass+1)); else fail=$((fail+1)); fi; }
refused_case()  ( fixture "case$n"; changelog "$2"; expect_refused "$1" )
released_case() ( fixture "case$n"; changelog "$2"; expect_released "$1" )
refuse() { n=$((n+1)); tally refused_case "$@"; }  # refuse <name> <changelog-body>
accept() { n=$((n+1)); tally released_case "$@"; } # accept <name> <changelog-body>

echo "=== push: only the named tag is published ==="
follow_tags() (
	fixture follow-tags
	changelog "$HEADING"
	# After the fixture's own pushes, so only the recipe's push can publish it.
	git tag -a v0.0.9-unrelated -m unrelated HEAD~1
	git config --global push.followTags true
	expect_released "push.followTags=true does not publish an unrelated reachable annotated tag"
)
tally follow_tags

echo "=== CHANGELOG guard: a heading counts only outside a fenced code block ==="
refuse "backtick-fenced heading only" \
	"$(printf 'Example:\n\n%smarkdown\n%s\n%s\n' "$FENCE" "$HEADING" "$FENCE")"
refuse "tilde-fenced heading only" \
	"$(printf '~~~\n%s\n~~~\n' "$HEADING")"
refuse "a shorter fence line does not close a longer fence" \
	"$(printf '%s\n%s\n%s\n%s\n' "$LONG_FENCE" "$FENCE" "$HEADING" "$LONG_FENCE")"
refuse "a tilde line does not close a backtick fence" \
	"$(printf '%s\n~~~\n%s\n%s\n' "$FENCE" "$HEADING" "$FENCE")"
refuse "an unclosed fence runs to the end of the file" \
	"$(printf '%s\n%s\n' "$FENCE" "$HEADING")"
refuse "a fence indented three spaces is still a fence" \
	"$(printf '   %s\n%s\n   %s\n' "$FENCE" "$HEADING" "$FENCE")"
accept "a real heading after a closed fenced example" \
	"$(printf '%smarkdown\n%s\n%s\n\n%s\n' "$FENCE" "$HEADING" "$FENCE" "$HEADING")"
accept "a line indented four spaces is indented code, not a fence" \
	"$(printf '    %s\n\n%s\n' "$FENCE" "$HEADING")"

# ---------------------------------------------------------------------------
# public / lockstep (automatethethings#173). Generic helpers: a case runs
# `make <args>` and asserts either the exact set of tags on the remote, or a
# refusal that left the clone and the remote untouched.

mk() { make -s "$@" >"$ROOT/out" 2>&1; }

# pin <require-line> — commit and publish a require in the root go.mod.
pin() {
	printf 'module github.com/jeremyhahn/fixture\n\ngo 1.24\n\nrequire (\n\t%s\n)\n' "$1" > go.mod
	git commit -q -am pin
	git push -q origin main
}

# remote_tag <tag> — put an annotated tag on HEAD on the remote only.
remote_tag() { git tag -a "$1" -m "$1" HEAD && git push -q origin "refs/tags/$1" && git tag -d "$1" >/dev/null; }

# expect_tags <name> <want> <make args...> — make succeeds; the remote's tags
# are exactly <want> (sorted, space-separated); every tag this run added peels
# to the remote's main, which is the release commit; VERSION matches.
expect_tags() {
	local name="$1" want="$2"; shift 2
	local before; before="$(remote_tags)"
	if ! mk "$@"; then bad "$name" "recipe refused: $(tail -n1 "$ROOT/out")"; return 1; fi
	local tags; tags="$(remote_tags)"
	[ "$tags" = "$want" ] || { bad "$name" "remote tags are [$tags], want [$want]"; return 1; }
	local main t; main="$(git ls-remote origin refs/heads/main | cut -f1)"
	[ "$main" = "$(git rev-parse HEAD)" ] || { bad "$name" "remote main is not the release commit"; return 1; }
	for t in $tags; do
		case " $before" in *" $t "*) continue ;; esac
		[ "$(git rev-parse "refs/tags/$t^{commit}")" = "$main" ] || { bad "$name" "tag $t is not on the release commit"; return 1; }
		[ "$(git cat-file -t "refs/tags/$t")" = tag ] || { bad "$name" "tag $t is not annotated"; return 1; }
	done
	local a
	for a in "$@"; do case "$a" in VERSION=*)
		[ "$(cat VERSION)" = "${a#VERSION=v}" ] || { bad "$name" "VERSION file is $(cat VERSION), want ${a#VERSION=v}"; return 1; }
	esac; done
	ok "$name"
}

# expect_refusal <name> <reason-regex> <make args...> — make fails for the
# stated reason, and nothing was written, committed, tagged or pushed.
expect_refusal() {
	local name="$1" why="$2"; shift 2
	local head vfile tags; head="$(git rev-parse HEAD)"; vfile="$(cat VERSION)"; tags="$(remote_tags)"
	local ltags; ltags="$(git tag | sort | tr '\n' ' ')"
	if mk "$@"; then bad "$name" "recipe released"; return 1; fi
	grep -Eq "$why" "$ROOT/out" || { bad "$name" "refused for the wrong reason: $(tail -n1 "$ROOT/out")"; return 1; }
	[ "$(git rev-parse HEAD)" = "$head" ] || { bad "$name" "a commit was made"; return 1; }
	[ "$(cat VERSION)" = "$vfile" ] || { bad "$name" "VERSION was written"; return 1; }
	[ -z "$(git status --porcelain)" ] || { bad "$name" "working tree was modified"; return 1; }
	[ "$(git tag | sort | tr '\n' ' ')" = "$ltags" ] || { bad "$name" "a local tag was created"; return 1; }
	[ "$(remote_tags)" = "$tags" ] || { bad "$name" "a tag reached the remote"; return 1; }
	ok "$name"
}

PUB=v0.1.0
PUB_HEAD="## [${PUB#v}]"
rcase() { n=$((n+1)); tally "$@"; }

echo "=== release: version form ==="
pub_form() ( fixture "pubform$n"; changelog "$PUB_HEAD"
	local v
	for v in v0.1.0-rc.1 v0.1.0-alpha v0.1 v0.01.0 v01.0.0 v0.1.0.1 0.1.0; do
		expect_refusal "refuses VERSION=$v" 'not of the form vX.Y.Z' release VERSION="$v" || return 1
	done
	expect_refusal "refuses an empty VERSION" 'state the version explicitly' release )
rcase pub_form
pub_ok() ( fixture "pubok$n"; changelog "$PUB_HEAD"
	expect_tags "cuts vX.Y.Z on main and pushes only that tag" "$PUB " release VERSION="$PUB" )
rcase pub_ok
pub_changelog() ( fixture "pubchg$n"; changelog "$HEADING"
	expect_refusal "refuses without a ## [X.Y.Z] heading (an alpha's heading does not count)" 'CHANGELOG.md has no' release VERSION="$PUB" )
rcase pub_changelog
pub_dup() ( fixture "pubdup$n"; changelog "$PUB_HEAD"
	remote_tag "$PUB"
	expect_refusal "refuses a vX.Y.Z tag that already exists on the remote" "tag $PUB already exists on origin" release VERSION="$PUB" )
rcase pub_dup
# An alpha of the next version may follow a release on main.
pub_then_alpha() ( fixture "pubal$n"; changelog "$PUB_HEAD"
	mk release VERSION="$PUB" || { bad "alpha after release" "release refused: $(tail -n1 "$ROOT/out")"; return 1; }
	changelog "$(printf '%s\n\n%s\n' '## [0.1.1-alpha]' "$PUB_HEAD")"
	expect_tags "an alpha of the next version may follow a release" "$PUB v0.1.1-alpha " release-alpha VERSION=v0.1.1-alpha )
rcase pub_then_alpha

echo "=== release-candidate: version form, kinds and ordering ==="
RC=v0.1.0-rc.1
RC_HEAD="## [${RC#v}]"
rc_form() ( fixture "rcform$n"; changelog "$RC_HEAD"
	local v
	for v in v0.1.0 v0.1.0-alpha v0.1.0-rc.0 v0.1.0-rc.01 v0.1.0-rc v0.1.0-rc.1.1 v0.1.0-RC.1 v0.01.0-rc.1 0.1.0-rc.1; do
		expect_refusal "refuses VERSION=$v" 'not of the form vX.Y.Z-rc.N' release-candidate VERSION="$v" || return 1
	done
	expect_refusal "refuses an empty VERSION" 'state the version explicitly' release-candidate || return 1
	expect_refusal "release-alpha refuses an -rc.N VERSION" 'not of the form vX.Y.Z-alpha' release-alpha VERSION="$RC" )
rcase rc_form
rc_ok() ( fixture "rcok$n"; changelog "$RC_HEAD"
	expect_tags "cuts vX.Y.Z-rc.N on main and pushes only that tag" "$RC " release-candidate VERSION="$RC" )
rcase rc_ok
rc_changelog() ( fixture "rcchg$n"; changelog "$PUB_HEAD"
	expect_refusal "refuses without a ## [X.Y.Z-rc.N] heading (the release's heading does not count)" 'CHANGELOG.md has no' release-candidate VERSION="$RC" )
rcase rc_changelog
rc_env() ( fixture "rcenv$n"; changelog "$RC_HEAD"
	VERSION="$RC" expect_refusal "refuses an exported VERSION" 'must be given on the make command line' release-candidate )
rcase rc_env
rc_order_case() ( fixture "rcord$n"; changelog "$(printf '%s\n\n%s\n' "## [${3#v}]" "$PUB_HEAD")"
	remote_tag "$2"
	if [ "$4" = ok ]; then expect_tags "$1" "$(printf '%s\n%s\n' "$2" "$3" | sort | tr '\n' ' ')" "$5" VERSION="$3"
	else expect_refusal "$1" 'does not order above existing release tags' "$5" VERSION="$3"; fi )
rc_order() { n=$((n+1)); tally rc_order_case "$@"; }
rc_order "a candidate orders above its own alpha"          v0.1.0-alpha v0.1.0-rc.1 ok      release-candidate
rc_order "rc.2 orders above rc.1"                          v0.1.0-rc.1  v0.1.0-rc.2 ok      release-candidate
rc_order "refuses rc.1 once rc.2 exists"                   v0.1.0-rc.2  v0.1.0-rc.1 refused release-candidate
rc_order "refuses a candidate of a released version"       v0.1.0       v0.1.0-rc.1 refused release-candidate
rc_order "a release orders above its candidates"           v0.1.0-rc.2  v0.1.0      ok      release
rc_lockstep() ( fixture "rcls$n" "sdk/go"; changelog "$RC_HEAD"
	expect_tags "a candidate tags the root and its lockstep modules on one commit" \
		"$(printf '%s\n%s\n' "$RC" "sdk/go/$RC" | sort | tr '\n' ' ')" release-candidate VERSION="$RC" )
rcase rc_lockstep

echo "=== version ordering: SemVer §11 precedence over existing tags ==="
# order <name> <existing-tag> <version> <want: ok|refused>
order_case() ( fixture "ord$n"; changelog "## [${3#v}]"
	remote_tag "$2"
	if [ "$4" = ok ]; then expect_tags "$1" "$(printf '%s\n%s\n' "$2" "$3" | sort | tr '\n' ' ')" release VERSION="$3"
	else expect_refusal "$1" 'does not order above existing release tags' release VERSION="$3"; fi )
order() { n=$((n+1)); tally order_case "$@"; }
order "refuses a release below a later alpha"            v0.1.1-alpha   v0.1.0   refused
order "refuses a release below a released version"       v0.2.0         v0.1.9   refused
order "a release orders above its own alpha"             v0.1.0-alpha   v0.1.0   ok
order "a release orders above its numbered pre-releases" v0.1.0-beta.11 v0.1.0   ok
order "0.10.0 orders above 0.9.0 (numeric minor)"        v0.9.0         v0.10.0  ok

order_mod() ( fixture "ordm$n" "sdk/go"; changelog "$PUB_HEAD"
	remote_tag sdk/go/v0.5.0
	expect_refusal "refuses when a lockstep module is already versioned above the release" 'sdk/go/v0.5.0' release VERSION="$PUB" )
rcase order_mod
order "numbers beyond float precision compare exactly" v0.9999999999999999998.0 v0.9999999999999999999.0 ok
order "...and a lower huge number is refused"          v0.9999999999999999999.0 v0.9999999999999999998.0 refused
vfile_case() ( fixture "vf$n"; changelog "$PUB_HEAD"
	printf '0.1.0\n0.9.0\n' > VERSION; git commit -q -am twolines; git push -q origin main
	expect_refusal "refuses a VERSION file of more than one line" 'exactly one line' release VERSION="$PUB" || return 1
	printf '0.6.0-alpha\n' > VERSION; git commit -q -am ahead; git push -q origin main
	expect_refusal "refuses a release that would lower an untagged forward VERSION" 'would lower it' release VERSION="$PUB" || return 1
	printf '0.1.0\n' > VERSION; git commit -q -am equal; git push -q origin main
	expect_tags "accepts a release equal to VERSION" "$PUB " release VERSION="$PUB" )
rcase vfile_case
path_case() ( fixture "path$n"; changelog "$PUB_HEAD"
	mkdir -p "$ROOT/path$n/pbin" && cp "$ROOT/path$n/agent-git" "$ROOT/path$n/pbin/agent-git.sh"
	PATH="$ROOT/path$n/pbin:$PATH" expect_tags "AGENT_GIT=agent-git.sh resolves through PATH" "$PUB " release VERSION="$PUB" AGENT_GIT=agent-git.sh || return 1
	expect_refusal "an AGENT_GIT that resolves nowhere is refused" 'AGENT_GIT does not resolve' release VERSION=v0.1.1 AGENT_GIT=no-such-agent-git.sh )
rcase path_case

echo "=== lockstep modules: every module tag, one atomic push ==="
ls_pub() ( fixture "lspub$n" "sdk/go xkey"; changelog "$PUB_HEAD"
	# The root requires sdk/go too: a require cycle, fixed in one commit (§5).
	printf 'module github.com/jeremyhahn/fixture\n\ngo 1.24\n\nrequire github.com/jeremyhahn/fixture/sdk/go v0.0.1-alpha\n' > go.mod
	git commit -q -am cycle && git push -q origin main
	expect_tags "public tags the root, sdk/go and xkey on the release commit" \
		"sdk/go/$PUB $PUB xkey/$PUB " release VERSION="$PUB" || return 1
	local f want
	for f in go.mod sdk/go/go.mod xkey/go.mod; do
		want='github.com/jeremyhahn/fixture'; [ "$f" = go.mod ] && want='github.com/jeremyhahn/fixture/sdk/go'
		git show "$PUB:$f" | grep -Eq "^require $want $PUB\$" || { bad "own-module pins move with the release" "$f at $PUB: $(git show "$PUB:$f" | grep require)"; return 1; }
	done
	ok "own-module pins (root <-> sdk/go, xkey -> root) move to the release version in the release commit" )
rcase ls_pub
ls_alpha() ( fixture "lsal$n" "sdk/go"; changelog "$HEADING"
	expect_tags "alpha tags lockstep modules too" "sdk/go/$VER $VER " release-alpha VERSION="$VER" )
rcase ls_alpha
ls_dup() ( fixture "lsdup$n" "sdk/go xkey"; changelog "$PUB_HEAD"
	remote_tag "xkey/$PUB"
	expect_refusal "refuses when one module tag already exists on the remote" "tag xkey/$PUB already exists on origin" release VERSION="$PUB" )
rcase ls_dup
ls_nomod() ( fixture "lsnm$n" "sdk/go"; changelog "$PUB_HEAD"
	expect_refusal "refuses a lockstep entry with no tracked go.mod" 'has no tracked go.mod' release VERSION="$PUB" LOCKSTEP_MODULES='sdk/go web' &&
	expect_refusal "refuses a lockstep entry that climbs out of the repo" 'not a plain repo-relative directory' release VERSION="$PUB" LOCKSTEP_MODULES='../x' &&
	expect_refusal "refuses a lockstep entry listed twice" 'lists sdk/go twice' release VERSION="$PUB" LOCKSTEP_MODULES='sdk/go sdk/go' )
rcase ls_nomod
ls_refname() ( fixture "lsrf$n" "sdk.lock"; changelog "$PUB_HEAD"
	expect_refusal "refuses a module whose tag would not be a valid ref, before writing anything" 'not a valid tag name' release VERSION="$PUB" )
rcase ls_refname
ls_atomic() ( fixture "lsat$n" "sdk/go"; changelog "$PUB_HEAD"
	# A remote that rejects one module tag must receive none of them.
	# shellcheck disable=SC2016 # $1 belongs to the hook, not to this shell
	printf '#!/bin/sh\n[ "$1" = refs/tags/sdk/go/%s ] && exit 1\nexit 0\n' "$PUB" > "$ROOT/lsat$n/remote.git/hooks/update"
	chmod +x "$ROOT/lsat$n/remote.git/hooks/update"
	mk release VERSION="$PUB" && { bad "a rejected module tag fails the release" "recipe succeeded"; return 1; }
	[ -z "$(remote_tags)" ] || { bad "a rejected module tag fails the release" "remote has [$(remote_tags)]"; return 1; }
	ok "a rejected module tag fails the whole push: no root tag lands alone" )
rcase ls_atomic
ls_omitted() ( fixture "lsom$n" "sdk/go xkey"; changelog "$(printf '%s\n\n%s\n' "$PUB_HEAD" "$HEADING")"
	remote_tag xkey/v0.0.1-alpha
	expect_refusal "public refuses when a released module is left out of LOCKSTEP_MODULES" 'xkey is a released module' release VERSION="$PUB" LOCKSTEP_MODULES=sdk/go || return 1
	expect_tags "an alpha may still leave it out (adopters tag modules by their own targets)" "$VER xkey/v0.0.1-alpha " release-alpha VERSION="$VER" LOCKSTEP_MODULES= )
rcase ls_omitted

echo "=== upstream gate (release-versioning.md §1a): first-party pins must be vA.B.C ==="
gate_pub() ( fixture "gate$n" "sdk/go"; changelog "$PUB_HEAD"
	pin 'github.com/jeremyhahn/go-codec v1.4.0-alpha'
	expect_refusal "public refuses a first-party -alpha pin" 'go-codec@v1.4.0-alpha' release VERSION="$PUB" || return 1
	pin 'github.com/jeremyhahn/go-codec v1.4.0-rc.2'
	expect_refusal "public refuses a first-party -rc pin" 'go-codec@v1.4.0-rc.2' release VERSION="$PUB" || return 1
	pin 'github.com/jeremyhahn/go-codec v0.0.0-20260901000000-abcdefabcdef'
	expect_refusal "public refuses a first-party pseudo-version" 'first-party dependencies' release VERSION="$PUB" || return 1
	pin 'github.com/jeremyhahn/go-codec v1.4.0 // indirect'
	expect_tags "public accepts a vA.B.C pin; own-module alpha pins are exempt" "sdk/go/$PUB $PUB " release VERSION="$PUB" )
rcase gate_pub
gate_placeholder() ( fixture "gatep$n"; changelog "$PUB_HEAD"
	pin 'github.com/jeremyhahn/go-codec v0.0.0'
	expect_refusal "public refuses the v0.0.0 placeholder pin" 'go-codec@v0.0.0' release VERSION="$PUB" )
rcase gate_placeholder
gate_third() ( fixture "gate3$n"; changelog "$PUB_HEAD"
	pin 'github.com/other/lib v0.2.0-alpha'
	expect_tags "public ignores a third-party prerelease pin" "$PUB " release VERSION="$PUB" )
rcase gate_third
major_case() ( fixture "maj$n"; changelog "## [2.0.0]"
	expect_refusal "refuses a v2 release of a module path without /v2" 'needs the module path to end in /v2' release VERSION=v2.0.0 || return 1
	printf 'module github.com/jeremyhahn/fixture/v2\n\ngo 1.24\n' > go.mod; git commit -q -am v2; git push -q origin main
	expect_tags "accepts a v2 release of a /v2 module path" "v2.0.0 " release VERSION=v2.0.0 || return 1
	printf 'module github.com/jeremyhahn/fixture/v3\n\ngo 1.24\n' > go.mod; git commit -q -am v3; git push -q origin main
	changelog "## [2.0.1]"
	expect_refusal "refuses a v2 release of a /v3 module path" 'end in /v2' release VERSION=v2.0.1 )
rcase major_case
major_v1() ( fixture "majv1$n"; changelog "$PUB_HEAD"
	printf 'module github.com/jeremyhahn/fixture/v1\n\ngo 1.24\n' > go.mod; git commit -q -am v1; git push -q origin main
	expect_refusal "refuses a v0/v1 release of a /v1 module path" 'carries no /vN suffix' release VERSION="$PUB" )
rcase major_v1
pub_zero() ( fixture "pz$n"; changelog "## [0.0.0]"
	expect_refusal "refuses the v0.0.0 placeholder as a release" 'legacy placeholder' release VERSION=v0.0.0 )
rcase pub_zero
alpha_order() ( fixture "ao$n" "sdk/go"; changelog "$HEADING"
	git tag -a sdk/go/v0.5.0-alpha -m ahead HEAD && git push -q origin refs/tags/sdk/go/v0.5.0-alpha && git tag -d sdk/go/v0.5.0-alpha >/dev/null
	expect_refusal "alpha refuses when a lockstep module is already versioned above it" 'sdk/go/v0.5.0-alpha' release-alpha VERSION="$VER" )
rcase alpha_order
sparse_case() ( fixture "sp$n" "sdk/go"; changelog "$HEADING"
	git sparse-checkout set --no-cone '/*' '!/sdk/' >/dev/null 2>&1 || { bad "sparse" "could not set up a sparse checkout"; return 1; }
	expect_refusal "refuses a lockstep module whose go.mod is not checked out" 'not checked out' release-alpha VERSION="$VER" )
rcase sparse_case
sparse_root() ( fixture "spr$n"; changelog "$PUB_HEAD"
	git sparse-checkout set --no-cone '/*' '!/go.mod' >/dev/null 2>&1 || { bad "sparse root" "could not set up a sparse checkout"; return 1; }
	expect_refusal "refuses a root go.mod that is tracked but not checked out" 'skip the root module' release VERSION="$PUB" )
rcase sparse_root
edit_fail() ( fixture "edf$n" "sdk/go"; changelog "$PUB_HEAD"
	# A go that exists but cannot edit (a stale local toolchain, say).
	mkdir -p "$ROOT/edf$n/fakego" && printf '#!/bin/sh\nexit 1\n' > "$ROOT/edf$n/fakego/go" && chmod +x "$ROOT/edf$n/fakego/go"
	PATH="$ROOT/edf$n/fakego:$PATH" expect_refusal "a go mod edit that fails is caught on a copy; the tree stays clean" 'tried on a copy' release VERSION="$PUB" )
rcase edit_fail

echo "=== GitHub is never a release remote; a release VERSION comes from the command line ==="
gh_remote() ( fixture "ghr$n"; changelog "$(printf '%s\n\n%s\n' "$PUB_HEAD" "$HEADING")"
	git remote add github "$ROOT/ghr$n/remote.git"
	expect_refusal "refuses RELEASE_REMOTE=github" 'RELEASE_REMOTE is github' release VERSION="$PUB" RELEASE_REMOTE=github || return 1
	expect_refusal "alpha refuses RELEASE_REMOTE=github too" 'RELEASE_REMOTE is github' release-alpha VERSION="$VER" RELEASE_REMOTE=github || return 1
	git remote remove github
	git remote set-url --push origin git@github.com:jeremyhahn/fixture.git
	expect_refusal "refuses a Gitea remote whose pushurl is github.com" 'pushes to github.com' release VERSION="$PUB" || return 1
	git remote set-url --push --delete origin github.com
	git config --global "url.git@github.com:jeremyhahn/.pushInsteadOf" "$ROOT/ghr$n/"
	expect_refusal "refuses a pushInsteadOf rewrite to github.com" 'pushes to github.com' release VERSION="$PUB" )
rcase gh_remote
env_version() ( fixture "envv$n"; changelog "$PUB_HEAD"
	VERSION="$PUB" expect_refusal "refuses an exported VERSION" 'must be given on the make command line' release || return 1
	VERSION="$PUB" expect_refusal "refuses VERSION from the environment under make -e" 'must be given on the make command line' -e release )
rcase env_version

echo "=== command-line injection: new inputs and the canned sequences ==="
inject() ( fixture "inj$n"; changelog "$(printf '%s\n\n%s\n' "$PUB_HEAD" "$HEADING")"
	# Each value would create the canary if Make expanded it. A release may
	# still happen (an overridden canned sequence is ignored, not an error);
	# what must never happen is the payload running.
	local canary="$ROOT/inj$n/canary" a r
	for r in "release VERSION=$PUB" "release-candidate VERSION=$RC" "release-alpha VERSION=$VER"; do
		for a in "LOCKSTEP_MODULES=\$(shell touch $canary)" "REL_MODULES=\$(shell touch $canary)" \
			"REL_VERSION_ORIGIN=\$(shell touch $canary)" \
			"RELEASE_CUT=\$(shell touch $canary)" "RELEASE_GUARDS=\$(shell touch $canary)" \
			"RELEASE_PIN_GATE=\$(shell touch $canary)" "RELEASE_MONOTONIC=\$(shell touch $canary)"; do
			# shellcheck disable=SC2086 # $r is the target and its VERSION, split on purpose
			mk $r "$a" || true
			[ ! -e "$canary" ] || { bad "injection" "payload fired via ${a%%=*} (${r%% *})"; return 1; }
		done
	done
	ok "no payload fires via LOCKSTEP_MODULES, REL_* or the canned sequences, on any recipe" )
rcase inject

echo
echo "release templates: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
