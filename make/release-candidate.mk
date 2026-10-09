# release-candidate-template: v1.0.0 (2026-10-08). Cuts the Gitea tag of a
# RELEASE CANDIDATE (release-versioning.md §1a): vX.Y.Z-rc.N on main, a
# pre-release of the public vX.Y.Z. N starts at 1 and increments per candidate.
# The kind was restored by the owner on 2026-10-07, and its target named:
# "lets name the release candidate target release-candidate and the
# production release simply make release." It refuses the other kinds: an
# alpha is release-alpha.mk, a release is release.mk.
#
#   make release-candidate VERSION=vX.Y.Z-rc.N
#
# §1a's gate for a candidate is CI green on main and the post-tag consumer
# check (§2, "Post-tag verification"); run that check after this recipe has cut
# the tag. This recipe pushes to RELEASE_REMOTE (Gitea) only.
#
# Adopt beside release-common.mk with the same variables as release-alpha.mk.
#
# What this recipe checks, beyond the alpha recipe's guards:
#   - VERSION is vX.Y.Z-rc.N (no leading zeroes, N >= 1) and must be given on
#     the make command line; an exported or inherited VERSION is refused.
#   - Every nested module already released under a <dir>/v* tag is listed in
#     LOCKSTEP_MODULES (release-common.mk RELEASE_LOCKSTEP_COMPLETE).
#   - VERSION orders strictly above every release tag already on the remote,
#     by SemVer §11 precedence (an -rc.N orders above the same version's
#     -alpha and below vX.Y.Z), and not below the VERSION file
#     (release-common.mk RELEASE_MONOTONIC).
#   - The major agrees with every published module path's /vN suffix
#     (release-common.mk RELEASE_MAJOR_GATE).
#   - No upstream pin gate: §1a names none for a candidate. release.mk's
#     vA.B.C gate applies to the release itself.
.PHONY: release-candidate
include $(dir $(lastword $(MAKEFILE_LIST)))release-common.mk
release-candidate:
	@test -n "$$REL_VERSION" || { echo 'ERROR: state the version explicitly: make release-candidate VERSION=vX.Y.Z-rc.N'; exit 1; }
	@printf '%s' "$$REL_VERSION" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-rc\.[1-9][0-9]*$$' || { echo "ERROR: VERSION is not of the form vX.Y.Z-rc.N (no leading zeroes, N >= 1): $$REL_VERSION"; exit 1; }
	@test "$$REL_VERSION_ORIGIN" = "command line" || { echo "ERROR: VERSION must be given on the make command line; it came from: $$REL_VERSION_ORIGIN (an exported or inherited VERSION is refused for a release candidate tag)"; exit 1; }
	$(RELEASE_GUARDS)
	$(RELEASE_LOCKSTEP_COMPLETE)
	$(RELEASE_MONOTONIC)
	$(RELEASE_MAJOR_GATE)
	$(RELEASE_CUT)
