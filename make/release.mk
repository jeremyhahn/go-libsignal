# release-template: v3.0.0 (2026-10-08). Cuts the Gitea tag of a PUBLIC release
# (release-versioning.md §1a): vX.Y.Z, no suffix, on main. v3.0.0 renames
# release-public.mk / `make release-public` to release.mk / `make release`; the
# owner, 2026-10-07: "lets name the release candidate target release-candidate
# and the production release simply make release." It refuses the other kinds.
# A release candidate is release-candidate.mk; an alpha, release-alpha.mk.
# v2.0.0 (2026-09-27 — automatethethings#173), release-public-template, dropped
# the RC parameter; the owner, 2026-09-26: "we are following the github flow
# which means we should just be branching and merging to master and using tags
# for the release." The -rc.N kind returned on 2026-10-07 as its own recipe.
#
#   make release VERSION=vX.Y.Z
#
# RUN IT ONLY AFTER THE OWNER HAS CONFIRMED THE PUBLIC VERSION NUMBER (§1a: the
# owner's per-push approval "also confirms the public version number"). A tag
# is immutable (§3); a number tagged before it is confirmed is spent. This
# recipe pushes to RELEASE_REMOTE (Gitea) only — publishing to GitHub is
# software/scripts/github-publish.sh, gated separately on the owner's per-push
# instruction (version-control.md §5a).
#
# Adopt beside release-common.mk with the same variables as release-alpha.mk.
#
# What this recipe adds to the alpha recipe:
#   - VERSION is vX.Y.Z and must be given on the make command line; an
#     exported or inherited VERSION is refused.
#   - Every nested module already released under a <dir>/v* tag must be listed
#     in LOCKSTEP_MODULES (release-common.mk RELEASE_LOCKSTEP_COMPLETE).
#   - VERSION orders strictly above every release tag already on the remote,
#     by SemVer §11 precedence, and not below the VERSION file
#     (release-common.mk RELEASE_MONOTONIC).
#   - The release's major agrees with every published module path's /vN
#     suffix (release-common.mk RELEASE_MAJOR_GATE).
#   - UPSTREAM GATE: every first-party requirement in the root go.mod and each
#     lockstep module's go.mod must be a public release, vA.B.C. This is not
#     policy but resolvability: GitHub consumers cannot fetch a Gitea-only
#     alpha or a pseudo-version, so a public module pinning one is broken for
#     everyone who installs it. Whether each such upstream tag is actually
#     PUBLISHED on GitHub is checked by github-publish.sh before it pushes;
#     this recipe talks to Gitea only.
#
# The shared guards (RELEASE_GUARDS) already refuse a vX.Y.Z or <dir>/vX.Y.Z
# tag that exists locally or on the remote.
#
# REVIEW: github-publish.sh needs an approved release-review record for this
# tag's exact tree. A lockstep release rewrites its own-module go.mod pins in
# the release commit, so review the tag, `release-review.sh <repo> vX.Y.Z`,
# after this recipe has cut it.
.PHONY: release
include $(dir $(lastword $(MAKEFILE_LIST)))release-common.mk
release:
	@test -n "$$REL_VERSION" || { echo 'ERROR: state the version explicitly: make release VERSION=vX.Y.Z (the owner confirms the public number)'; exit 1; }
	@printf '%s' "$$REL_VERSION" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$$' || { echo "ERROR: VERSION is not of the form vX.Y.Z (no suffix, no leading zeroes): $$REL_VERSION"; exit 1; }
	@test "$$REL_VERSION" != v0.0.0 || { echo 'ERROR: v0.0.0 is the legacy placeholder, never a release (release-versioning.md §2)'; exit 1; }
	@test "$$REL_VERSION_ORIGIN" = "command line" || { echo "ERROR: VERSION must be given on the make command line; it came from: $$REL_VERSION_ORIGIN (an exported or inherited VERSION is refused for a release tag)"; exit 1; }
	$(RELEASE_GUARDS)
	$(RELEASE_LOCKSTEP_COMPLETE)
	$(RELEASE_MONOTONIC)
	$(RELEASE_MAJOR_GATE)
	@pin_re='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$$'; $(RELEASE_PIN_GATE)
	$(RELEASE_CUT)
