# Makefile for go-libsignal
# Signal Protocol library for Go

# ==============================================================================
# Configuration
# ==============================================================================

MODULE := github.com/jeremyhahn/go-libsignal
VERSION := $(shell cat VERSION 2>/dev/null || echo "0.0.0")
# Every test target carries an explicit -timeout. Go's default is 600s per test
# binary, and pkg/session alone measured 178.7s on an idle CI runner -- only
# 3.4x headroom on a host measured varying 2.9x-8.7x between runs. On
# 2026-08-19 that cliff was hit: pkg/session died at 600s while every other
# package, none of them touched, inflated 2.9x-8.7x from contention alone.
#
# 900s is the per-TEST-BINARY budget, not the job's. Measured on that run: the
# job spent 777s of wall clock against ci.yml's 1800s cap, so letting a package
# reach 900s still leaves the Go timeout -- which names the package and dumps
# goroutines -- firing well before the job timeout, which reports nothing.
#
# GOTEST_TIMEOUT governs EVERY suite, the FIPS gate included. Overriding it, or
# overriding GOTEST wholesale, relaxes the compliance gate along with the rest.
GOTEST_TIMEOUT := 900s
GOTEST := go test -timeout=$(GOTEST_TIMEOUT)
GOVET := go vet
GOBUILD := go build

# PINNED (devops.md §9, documented): v2.13.0 (2026-08-19) ships
# honnef.co/go/tools v0.8.0-rc.1 whose nilness pass panics ("unhandled builtin
# recover", crashes on sentry-go) — red gate with zero findings. Unpin when
# golangci-lint ships a non-rc staticcheck that passes on main. Keep this in
# lockstep with the version the Lint job pins in .github/workflows/ci.yml —
# lint-pin-selftest asserts they agree, because CI runs the action rather than
# `make lint` and a drifted pin makes the two disagree about what a finding is.
#
# The pin is installed to $(GOLANGCI_LINT_BIN), NOT the shared $(GOBIN): the
# whole point of pinning away from v2.13.x is undone if a neighbouring lane can
# install over the binary this repo verified. It happened — the shared
# golangci-lint drifted to v2.13.1 for part of 2026-08-21.
GOLANGCI_LINT_VERSION := v2.12.2

# PINNED for REPRODUCIBILITY, not to dodge a bad release (devops.md §9).
# v0.8.1 is the latest and is clean on this tree -- unlike the golangci-lint pin
# above, which exists because v2.13.x is broken. The reason to pin at all is
# that $(GOBIN) is shared across every agent lane on this host: `which
# staticcheck` answers perfectly well for whatever version a neighbour last
# installed, so a presence test runs an analyser nobody chose. That is not
# hypothetical -- the shared golangci-lint drifted to v2.13.1 for part of
# 2026-08-21 by exactly that route.
#
# CI's Security Scan job deliberately installs @latest instead, on a clean
# runner where drift cannot happen: discovery of NEW SA findings is its job.
# When CI reports a finding a local run missed, bump this pin -- that is the
# intended workflow, not a mystery.
#
# The verification and the run happen in ONE shell command against
# $(STATICCHECK_BIN), so there is no window in which the checked binary and the
# executed binary can differ -- a check in one recipe line and a bare
# `staticcheck ./...` in the next is a TOCTOU race on a shared GOBIN.
#
# staticcheck reports two identities ("staticcheck 2026.2.1 (0.8.1)"): the
# release name and the module version. The parenthesised one is the module
# version, which is what `go install` takes.
STATICCHECK_VERSION := v0.8.1
COVERAGE_DIR := coverage
COVERAGE_SELFTEST_DIR := $(COVERAGE_DIR)/gate-selftest
COVERAGE_LOOP_SELFTEST_DIR := $(COVERAGE_DIR)/loop-selftest
COVERAGE_MIN := 90

# Per-package coverage minimums for packages with legitimately untestable branches.
# These packages contain defensive OOM panic-recovery blocks wrapping memguard
# allocations that cannot be triggered in unit tests without modifying OS mlock
# limits (CLAUDE.md prohibits host modification). All other packages must meet
# COVERAGE_MIN (90%).
#
#   pkg/groups/ratchet        87%  — OOM guards in NewSenderChainKey, Next,
#                                    NewSenderMessageKey, NewSenderMessageKeyFromStruct
#   pkg/mlkembraid            87%  — defensive invariant panics in Decoder.Reset /
#                                    Encoder.Reset; broad state-machine gaps tracked
#                                    separately; the package-total including sub-pkgs
#                                    is ≥90%
#   pkg/tripleratchet         87%  — multiple coverage-exempt paths:
#                                    (1) memguard OOM paths in takeSnapshot, Encrypt,
#                                    decryptWithSnapshot, kdf.go splitHybridOutput;
#                                    (2) dead code: uint32 overflow guard in
#                                    receivePQKey loop, KDFHybridECOnly branch;
#                                    (3) braid.Send never returns OutputKey in current
#                                    ML-KEM SCKA protocol;
#                                    (4) outputKey != nil in decryptWithSnapshot only
#                                    fires in fully synchronized bidirectional sessions
#                                    requiring a complete braid SCKA handshake, which
#                                    is not achievable with a simple symmetric EC cipher
#   pkg/util/crypto/secret    88%  — defer recover() OOM guards in New, NewRandom,
#                                    NewEmpty, and OpenEnclave
COVERAGE_MIN_groups_ratchet := 87
COVERAGE_MIN_mlkembraid := 87
COVERAGE_MIN_tripleratchet := 87
COVERAGE_MIN_util_crypto_secret := 88
GOBIN := $(shell go env GOPATH)/bin

# Analysers this repo pins live HERE, not in $(GOBIN). $(GOBIN) is shared across
# every agent lane on this host, so a version verified there can be replaced by
# a neighbour between the check and the run -- and installing into it makes this
# repo the thing that changes other lanes' tools. A repo-local directory removes
# both: nothing else writes to it, and the check and the run name the same path.
TOOLS_BIN := $(CURDIR)/.tools/bin
CI_WORKFLOW := .github/workflows/ci.yml
STATICCHECK_BIN := $(TOOLS_BIN)/staticcheck
STATICCHECK_LATEST_BIN := $(TOOLS_BIN)-latest/staticcheck
GOLANGCI_LINT_BIN := $(TOOLS_BIN)/golangci-lint

# The lint retry loop invokes $(LINT_CMD) rather than a bare `golangci-lint`,
# so lint-retry-selftest can drive it with a stub by overriding this variable.
# A stub planted on PATH would NOT work: the `export PATH` below prepends
# $(GOBIN), the real linter wins, and the self-test passes against any recipe.
LINT_CMD := $(GOLANGCI_LINT_BIN) run ./...
LINT_RETRY_MAX := 5
LINT_RETRY_DELAY := 10

export PATH := $(GOBIN):$(PATH)
export GOWORK := off

# All packages (excluding vendor and .git)
ALL_PACKAGES := $(shell go list ./... 2>/dev/null | grep -v /vendor/)

# Packages excluded from coverage reporting (generated code, test harness)
COVERAGE_EXCLUDE_PATTERN := /pkg/proto/|/svrpb|go-libsignal/tests$$|/state/store$$|/groups/state/store$$|/util/medium$$

# Testable packages (with actual source code, excluding store-only and proto)
TESTABLE_PACKAGES := pkg/accountkeys pkg/attest pkg/backup pkg/cipher pkg/devicetransfer pkg/ecc \
	pkg/fingerprint pkg/groups pkg/groups/ratchet pkg/groups/state/record pkg/incrementalmac \
	pkg/kdf pkg/kem pkg/keys/chain pkg/keys/identity pkg/keys/message pkg/keys/prekey pkg/keys/root \
	pkg/keys/session pkg/keytrans pkg/logger pkg/media pkg/mlkembraid pkg/net pkg/poksho pkg/protocol \
	pkg/ratchet pkg/sealed pkg/serialize pkg/sesame pkg/session pkg/spqr pkg/state/record pkg/svr \
	pkg/tripleratchet \
	pkg/usernames pkg/util/bytehelper pkg/util/crypto pkg/util/crypto/secret \
	pkg/util/errorhelper pkg/util/keyhelper pkg/util/optional pkg/crypto/elligator pkg/crypto/keyops \
	pkg/zkcredential pkg/zkgroup

.PHONY: all build test test-verbose integration-test test-interop \
	interop-fixtures-check interop-fixtures-refresh \
	interop-live-build interop-live interop-live-session interop-live-sealed \
	interop-live-group interop-live-backup interop-docker \
	vet lint _lint-retry lint-retry-selftest lint-pin-selftest \
	clean coverage coverage-gate-selftest _coverage-gate help \
	coverage-loop-selftest _coverage-collect \
	ci security gosec govulncheck staticcheck errcheck nilcheck \
	modverify trivy trivy-image staticcheck-latest staticcheck-selftest \
	fips fips-build fips-test \
	test-slow-session test-proptest test-proptest-selftest examples-build bench \
	_pkg_min_pkg_groups_ratchet _pkg_min_pkg_mlkembraid \
	_pkg_min_pkg_tripleratchet _pkg_min_pkg_util_crypto_secret

# The generated per-package targets are actions, never files, so they have to
# be .PHONY as well. `bench` above is the cautionary case rather than a
# hypothetical: a `bench/` DIRECTORY exists in this repo, so without the
# declaration make considered the target already satisfied and reported
# "'bench' is up to date" while running no benchmarks at all. Any name below
# acquires the same shadow the day someone adds a matching path.
.PHONY: $(addprefix test-,$(TESTABLE_PACKAGES)) \
	$(addprefix coverage-,$(TESTABLE_PACKAGES)) \
	$(addprefix bench-,$(TESTABLE_PACKAGES))

# ==============================================================================
# Build
# ==============================================================================

all: vet test build

build:
	@echo "Building go-libsignal v$(VERSION)"
	$(GOBUILD) ./...

# ==============================================================================
# Testing
# ==============================================================================

test:
	$(GOTEST) -race ./...

test-verbose:
	$(GOTEST) -race -v ./...

# No `| tee` here. A make recipe runs under /bin/sh without pipefail, so a
# pipeline exits with tee's status (always 0) and the target could never fail —
# `make integration-test` reported success on a failing suite. Callers that want
# a log file tee at the call site with pipefail set; ci.yml does.
integration-test:
	$(GOTEST) -race -v ./tests/...

# Slow tests: marked //go:build slow; excluded from make test.
# test_chain_jump_over_limit (rust/protocol/tests/session.rs:245):
#   Alice sends 25,001 messages without Bob decrypting, then sends one more.
#   Bob's decrypt must fail because the chain-key advance exceeds 25,000.
#   Expected runtime: ~60-120 s.
test-slow-session:
	GOWORK=off $(GOTEST) -race -count=1 -tags=slow -run TestRust_ChainJumpOverLimit ./pkg/session/...

# Property tests: marked //go:build proptest; excluded from make test.
#
# The four TestProptest_* cases are 167s of pkg/session's 213s -- 79% of the
# package. That left the 900s per-binary cap only 4.4x above a host measured
# varying 2.9x-8.7x between runs, and on 2026-08-21 the margin ran out: the
# whole Test job died on a timeout none of the other 225 tests caused (#30).
# They now run here, in their own CI job with their own budget. Raising
# GOTEST_TIMEOUT was the alternative and is worse -- it governs every suite
# including the FIPS gate.
#
# -run is a filter, not the selector: the build tag is what includes the file.
# The count check below is why both are safe. `go test -run` that matches
# nothing prints "ok ... [no tests to run]" and exits 0, so a target that only
# ran the command would pass just as loudly after someone renamed a test or
# dropped the tag. Deriving the expected count from the source means adding a
# fifth property test cannot silently escape the job either.
#
# The whole point of isolating these is giving them their OWN budget, so the
# target must not inherit GOTEST_TIMEOUT -- that is the 900s cap this split
# exists because they outgrew. 167s at the worst observed contention (8.7x) is
# ~1453s, which 900s does not cover; a separate job that still times out is
# just a smaller blast radius for the same failure.
#
# 2400s is 14.4x the measured 167s and 1.65x that worst case, and sits BELOW
# the job's 45-minute cap on purpose: Go's timeout has to fire first, because
# it names the package and dumps goroutines where the job timeout reports
# nothing. Keep that ordering if either number changes.
PROPTEST_TIMEOUT := 2400s
PROPTEST_FILE := pkg/session/proptest_session_test.go
PROPTEST_LOG := proptest.out

test-proptest:
	@expected=$$(grep -c '^func TestProptest_' $(PROPTEST_FILE)); \
	if [ "$$expected" -eq 0 ]; then \
		echo "FAIL: no TestProptest_ functions found in $(PROPTEST_FILE);"; \
		echo "      the file moved or was renamed, and this job would have"; \
		echo "      reported success while testing nothing."; \
		exit 1; \
	fi; \
	echo "expecting $$expected property tests from $(PROPTEST_FILE)"; \
	GOWORK=off go test -timeout=$(PROPTEST_TIMEOUT) -race -count=1 -tags=proptest -v -run '^TestProptest_' ./pkg/session/ > $(PROPTEST_LOG) 2>&1; \
	status=$$?; \
	cat $(PROPTEST_LOG); \
	ran=$$(grep -cE '^--- (PASS|FAIL): TestProptest_' $(PROPTEST_LOG) || true); \
	rm -f $(PROPTEST_LOG); \
	if [ "$$status" -ne 0 ]; then exit $$status; fi; \
	if [ "$$ran" -ne "$$expected" ]; then \
		echo "FAIL: $$ran property tests ran, but $$expected are declared in"; \
		echo "      $(PROPTEST_FILE). A property test that never runs is worse"; \
		echo "      than one that fails, because nothing says so."; \
		exit 1; \
	fi; \
	echo "PASS: all $$expected property tests ran"

# Self-test for the property-test target, in the shape of
# coverage-gate-selftest: check the properties that make the target worth
# having, rather than trusting that it still has them.
#
# The timeout checks are static because that is what they are about -- which
# timeout the recipe carries. The fail-closed check is behavioural and cheap:
# pointed at a file declaring no property tests, the target must exit non-zero
# without running anything.
test-proptest-selftest:
	@failures=0; \
	recipe=$$($(MAKE) -n test-proptest 2>/dev/null); \
	if [ "$(PROPTEST_TIMEOUT)" = "$(GOTEST_TIMEOUT)" ]; then \
		echo "BAD: PROPTEST_TIMEOUT equals GOTEST_TIMEOUT ($(GOTEST_TIMEOUT)) -- the"; \
		echo "     dedicated budget is the reason this target exists"; \
		failures=$$((failures + 1)); \
	else \
		echo "ok:  PROPTEST_TIMEOUT ($(PROPTEST_TIMEOUT)) differs from GOTEST_TIMEOUT ($(GOTEST_TIMEOUT))"; \
	fi; \
	case "$$recipe" in \
		*-timeout=$(PROPTEST_TIMEOUT)*) echo "ok:  recipe carries -timeout=$(PROPTEST_TIMEOUT)";; \
		*) echo "BAD: recipe does not carry -timeout=$(PROPTEST_TIMEOUT)"; failures=$$((failures + 1));; \
	esac; \
	case "$$recipe" in \
		*-timeout=$(GOTEST_TIMEOUT)*) \
			echo "BAD: recipe still carries the shared -timeout=$(GOTEST_TIMEOUT)"; \
			failures=$$((failures + 1));; \
		*) echo "ok:  recipe does not inherit GOTEST_TIMEOUT";; \
	esac; \
	probe=$$(mktemp); \
	echo 'package session_test' > $$probe; \
	if $(MAKE) -s --no-print-directory test-proptest PROPTEST_FILE=$$probe >/dev/null 2>&1; then \
		echo "BAD: target passed against a file declaring no property tests"; \
		failures=$$((failures + 1)); \
	else \
		echo "ok:  fails closed when no property tests are declared"; \
	fi; \
	rm -f $$probe; \
	if [ "$$failures" -ne 0 ]; then \
		echo "FAIL: property-test target self-test: $$failures check(s) failed"; \
		exit 1; \
	fi; \
	echo "PASS: property-test target self-test"
# Self-test for the pinned-TOOL property, in the shape of
# coverage-gate-selftest. The concurrency Codex raised on #33 cannot be
# reproduced by racing a real neighbour, so assert the two properties that make
# the race impossible instead:
#
#   1. the recipe EXECUTES the pinned path rather than a bare tool name that
#      PATH would resolve;
#   2. that path lies OUTSIDE $(GOBIN), so no other lane writes to what was
#      verified.
#
# Together those close the window: same path checked and run, on a directory
# nobody else touches.
#
# An earlier draft tried to prove (1) behaviourally, by planting a hostile
# `staticcheck` on PATH and checking the target ignored it. That check PASSED
# against a deliberately broken recipe -- the `export PATH` above prepends
# $(GOBIN) for every recipe, so the planted binary never won and the check could
# not fail for the reason it claimed. It is gone rather than left looking
# reassuring. lint-retry-selftest avoids the same trap by naming its stub through
# $(LINT_CMD) instead of planting it on PATH.
#
#   3. the recipe INSTALLS into that directory rather than the shared one.
#      Measured: without this, reverting `GOBIN=$(TOOLS_BIN) go install` to a
#      bare `go install` passed every other check. It fails closed at runtime
#      (the pinned path stays empty, so the version check exits 1), but it
#      still writes this repo's pin over whatever the neighbouring lanes are
#      using -- the second half of the property, and the half a self-test that
#      only reads paths cannot see.
#
# $(call assert_pinned,<label>,<target>,<pinned-bin>,<expected-invocation>,<expected-install>).
# Both pinned tools assert through this, so the property is defined once; a
# third pinned tool gets it by adding two lines, not by copying thirty.
define assert_pinned
	case "$$($(MAKE) -n $(2) 2>/dev/null)" in \
		*"$(4)"*) echo "ok:  $(1) recipe executes the pinned $(3)";; \
		*) echo "BAD: $(1) recipe does not execute $(4)"; failures=$$((failures + 1));; \
	esac; \
	case "$(3)" in \
		$(GOBIN)/*) \
			echo "BAD: $(3) is inside the shared $(GOBIN);"; \
			echo "     another lane can replace it between the check and the run"; \
			failures=$$((failures + 1));; \
		*) echo "ok:  $(1) pin lives outside the shared $(GOBIN)";; \
	esac; \
	case "$$($(MAKE) -n $(2) 2>/dev/null)" in \
		*"$(5)"*) echo "ok:  $(1) installs into the pinned directory, not $(GOBIN)";; \
		*) \
			echo "BAD: $(1) recipe does not install with $(5);"; \
			echo "     a bare 'go install' writes this repo's pin into the shared"; \
			echo "     $(GOBIN), changing what every other lane runs"; \
			failures=$$((failures + 1));; \
	esac;
endef

staticcheck-selftest:
	@failures=0; \
	$(call assert_pinned,staticcheck,staticcheck,$(STATICCHECK_BIN),$(STATICCHECK_BIN) ./...,GOBIN=$(TOOLS_BIN) go install honnef.co/go/tools) \
	case "$$(grep -A2 'Run staticcheck' $(CI_WORKFLOW) | grep 'make staticcheck')" in \
		*"make staticcheck-latest"*) echo "ok:  CI's Security Scan runs staticcheck-latest, not the pin";; \
		*) \
			echo "BAD: CI's Security Scan does not run make staticcheck-latest."; \
			echo "     A workflow that calls the pinned target gets the pin, so the"; \
			echo "     discovery gate would report success on the very version it"; \
			echo "     exists to improve on."; \
			failures=$$((failures + 1));; \
	esac; \
	case "$(STATICCHECK_LATEST_BIN)" in \
		$(STATICCHECK_BIN)) \
			echo "BAD: the latest and pinned analysers are the same path"; \
			failures=$$((failures + 1));; \
		*) echo "ok:  latest and pinned analysers are separate binaries";; \
	esac; \
	if [ "$$failures" -ne 0 ]; then \
		echo "FAIL: pinned-analyser self-test: $$failures check(s) failed"; \
		exit 1; \
	fi; \
	echo "PASS: pinned-analyser self-test"

# The same two properties for golangci-lint. It carried the defect longest: the
# version check ran against whatever PATH resolved and installed into the shared
# $(GOBIN), so the pin was only as good as the last neighbour to install there.
# Not hypothetical -- that binary drifted to v2.13.1 for part of 2026-08-21, and
# v2.13.x is the release whose nilness pass panics on this tree.
#
# `make -n` runs recursive sub-makes, so asserting on `lint` sees the real
# command line inside _lint-retry rather than the delegation to it.
#
# The expected invocation is spelled out from $(GOLANGCI_LINT_BIN) rather than
# passed as $(LINT_CMD). Measured: with $(LINT_CMD) on both sides, reverting the
# recipe to a bare PATH-resolved `golangci-lint run ./...` still PASSED -- the
# expectation moved with the mutation, so the check compared LINT_CMD to itself.
# $(LINT_CMD) is the thing under test here, not the yardstick.
lint-pin-selftest:
	@failures=0; \
	$(call assert_pinned,golangci-lint,lint,$(GOLANGCI_LINT_BIN),$(GOLANGCI_LINT_BIN) run ./...,GOBIN=$(TOOLS_BIN) go install github.com/golangci) \
	case "$$(grep -A3 'golangci-lint-action' $(CI_WORKFLOW) | grep 'version:')" in \
		*"$(GOLANGCI_LINT_VERSION)"*) echo "ok:  CI's Lint job pins the same $(GOLANGCI_LINT_VERSION)";; \
		*) \
			echo "BAD: CI's golangci-lint-action does not pin $(GOLANGCI_LINT_VERSION)."; \
			echo "     CI runs the action, not make lint, so a drifted pin here means"; \
			echo "     local runs and the gate disagree about what a finding is."; \
			failures=$$((failures + 1));; \
	esac; \
	if [ "$$failures" -ne 0 ]; then \
		echo "FAIL: pinned-linter self-test: $$failures check(s) failed"; \
		exit 1; \
	fi; \
	echo "PASS: pinned-linter self-test"

test-interop:
	GOWORK=off $(GOTEST) -race -v ./tests/interop/...

# Verify every fixture under tests/interop/fixtures/ matches its sha256 in
# MANIFEST.toml. With LIBSIGNAL_UPSTREAM=/path/to/libsignal-checkout the
# script additionally diffs each fixture against the upstream tree at the
# commit pinned in /RUST_REV. CI sets LIBSIGNAL_UPSTREAM.
interop-fixtures-check:
	tests/interop/scripts/check_fixtures.sh

# Refresh static fixtures from a local upstream Rust libsignal checkout.
# This is the only sanctioned way to update fixture bytes; after running it,
# regenerate the sha256 entries in MANIFEST.toml and bump /RUST_REV.
interop-fixtures-refresh:
	@if [ -z "$(LIBSIGNAL_UPSTREAM)" ]; then \
		echo "LIBSIGNAL_UPSTREAM must point at a Rust libsignal checkout" >&2; \
		exit 2; \
	fi
	tests/interop/scripts/refresh_fixtures.sh "$(LIBSIGNAL_UPSTREAM)"

# Phase 3b live interop targets: build and run the Rust CLI, then test with Go.
interop-live-build:
	cargo build --release --manifest-path tests/interop/rust/Cargo.toml \
		--bin libsignal-interop --bin interop_runner --bin wire_emitter

interop-live: interop-live-build
	LIBSIGNAL_INTEROP_BIN=$(CURDIR)/tests/interop/rust/target/release/libsignal-interop \
	LIBSIGNAL_INTEROP_LIVE_BIN=$(CURDIR)/tests/interop/rust/target/release/interop_runner \
	GOWORK=off $(GOTEST) -tags=interop_live -race -v ./tests/interop/live/...

interop-live-session:
	LIBSIGNAL_INTEROP_LIVE_BIN=$(CURDIR)/tests/interop/rust/target/release/interop_runner \
	GOWORK=off $(GOTEST) -tags=interop_live -race -v -run TestLiveInterop_SessionRoundTrip \
		./tests/interop/live/...

interop-live-sealed:
	LIBSIGNAL_INTEROP_LIVE_BIN=$(CURDIR)/tests/interop/rust/target/release/interop_runner \
	GOWORK=off $(GOTEST) -tags=interop_live -race -v -run TestLiveInterop_SealedSender \
		./tests/interop/live/...

interop-live-group:
	LIBSIGNAL_INTEROP_LIVE_BIN=$(CURDIR)/tests/interop/rust/target/release/interop_runner \
	GOWORK=off $(GOTEST) -tags=interop_live -race -v -run TestLiveInterop_SenderKey \
		./tests/interop/live/...

interop-live-backup:
	LIBSIGNAL_INTEROP_LIVE_BIN=$(CURDIR)/tests/interop/rust/target/release/interop_runner \
	GOWORK=off $(GOTEST) -tags=interop_live -race -v -run TestLiveInterop_Backup \
		./tests/interop/live/...

interop-docker:
	docker build -f tests/interop/Dockerfile -t libsignal-interop:local .
	docker run --rm libsignal-interop:local

# Regenerate wire-format fixtures from the pinned Rust libsignal upstream.
# Run manually when bumping /RUST_REV; the JSON fixtures are checked in and
# consumed by Go tests without a Rust toolchain.
.PHONY: interop-wire-emit
interop-wire-emit:
	cargo build --release --manifest-path tests/interop/rust/Cargo.toml --bin wire_emitter
	tests/interop/rust/target/release/wire_emitter \
		--out tests/interop/fixtures/wire/ \
		--frame-aes-out tests/interop/fixtures/messagebackup/frame_aes.json

# Package-specific test targets, named for the package PATH, not its base:
#   make test-pkg/cipher, make test-pkg/poksho, make test-pkg/keys/chain
$(addprefix test-,$(TESTABLE_PACKAGES)):
	$(GOTEST) -v ./$(subst test-,,$@)/...

# ==============================================================================
# FIPS 140-3 gate
# ==============================================================================

# GODEBUG=fips140=only puts the Go Cryptographic Module in the mode where a
# non-approved operation fails instead of quietly succeeding; fips140=on merely
# loads the module and still permits MD5, SHA-1 and friends, so a gate built on
# it cannot fail on the thing it exists to catch (configuration.md §5).
#
# These targets set GOFIPS140/GODEBUG themselves so a bare `make fips` locally
# reproduces the CI job exactly. ci.yml also sets them at the job level to stay
# aligned with the ci-template; the values are identical.
#
# The fips140only build tag excludes the tests listed in docs/FIPS.md -- the
# exemption register -- from the gate. Each entry there exercises a primitive
# that an external protocol or standard mandates and FIPS 140-3 does not
# approve, and carries the citation that mandates it. Production code is never
# tagged: `make fips-build` compiles the library exactly as it ships.
FIPS_ENV := GOFIPS140=latest GODEBUG=fips140=only

fips: fips-build fips-test

fips-build:
	$(FIPS_ENV) $(GOBUILD) ./...

fips-test:
	$(FIPS_ENV) $(GOTEST) -count=1 -tags fips140only ./...

# ==============================================================================
# Code Coverage
# ==============================================================================

# Fail-closed coverage gate.
#
#   $(1) coverage profile   $(2) minimum percentage   $(3) report label
#
# The percentage is validated before it is compared: an empty or non-numeric
# value means coverage could not be measured -- missing, empty or malformed
# profile, or a `go tool cover` failure -- and is a hard failure, never a pass.
# The comparison uses awk rather than bc so the gate carries no dependency
# whose absence would silently disable it (`bc` is absent from many CI images,
# and the previous `bc ... || echo 0` fallback turned that into a pass).
define coverage-gate
PCT=$$(go tool cover -func=$(1) | awk '/^total:/ { print $$3 }' | tr -d '%'); \
case "$$PCT" in \
	''|*[!0-9.]*) \
		echo "FAIL: $(3) coverage could not be measured from $(1) -- failing closed"; \
		exit 1 ;; \
esac; \
echo "=== $(3) COVERAGE: $$PCT% (min: $(2)%) ==="; \
awk -v pct="$$PCT" -v min="$(2)" 'BEGIN { \
	if (pct + 0 < min + 0) { printf "FAIL: coverage %s%% is below minimum %s%%\n", pct, min; exit 1 } \
	printf "PASS: coverage %s%% meets minimum %s%%\n", pct, min \
}'
endef

# Internal: runs the per-package collection over PKGS, appending each package's
# profile to PROFILE and failing if any package did not run to completion.
#
# Parameterised so the self-test below exercises the REAL loop rather than a
# copy of it -- the same arrangement _coverage-gate uses for the threshold.
#
# The two things this fixes are both fail-open holes, and they compound:
# `go test`'s exit status was ignored and its diagnostics went to /dev/null, so
# a package that failed, panicked or timed out contributed silently and the run
# moved on. A failing test still WRITES its coverage profile, so the resulting
# aggregate stayed perfectly well-formed and the threshold gate #13 added
# passed it honestly. Measured on this tree before the fix: with one package
# deliberately failing, `make coverage` exited 0 and reported the same 90.4% as
# a clean run.
_coverage-collect:
	@rm -f $(COVERAGE_DIR)/pkg.out
	@failed=""; \
	for pkg in $(PKGS); do \
		if ! $(GOTEST) -coverprofile=$(COVERAGE_DIR)/pkg.out -covermode=atomic "$$pkg"; then \
			failed="$$failed $$pkg"; \
		fi; \
		if [ -f $(COVERAGE_DIR)/pkg.out ]; then \
			if ! tail -n +2 $(COVERAGE_DIR)/pkg.out >> $(PROFILE); then \
				echo ""; \
				echo "FAIL: could not append $$pkg's profile to $(PROFILE)."; \
				echo "      Continuing would drop that package from the aggregate while"; \
				echo "      leaving the aggregate syntactically valid -- the same silent"; \
				echo "      contribution loss this loop exists to stop."; \
				exit 1; \
			fi; \
			if ! rm -f $(COVERAGE_DIR)/pkg.out; then \
				echo ""; \
				echo "FAIL: could not remove $(COVERAGE_DIR)/pkg.out after $$pkg."; \
				echo "      A package whose test writes no profile would then inherit"; \
				echo "      this one's, counting it twice and attributing it wrongly."; \
				exit 1; \
			fi; \
		fi; \
	done; \
	if [ -n "$$failed" ]; then \
		echo ""; \
		echo "FAIL: these packages did not run to completion:"; \
		for pkg in $$failed; do echo "        $$pkg"; done; \
		echo "      A percentage measured over the packages that did survive is a"; \
		echo "      real number for a broken tree, with nothing to mark it wrong, so"; \
		echo "      the run stops here instead of reporting one."; \
		exit 1; \
	fi

# Self-test for the fail-closed collection loop, in the shape of
# coverage-gate-selftest: drive the real recipe over inputs whose outcome is
# known, and check the outcome. Two ways a package's coverage can go missing,
# both of which used to be swallowed:
#
#   - the package does not run. An import path that cannot be loaded produces
#     no profile and exits nonzero.
#   - the package runs but its profile cannot be appended. A PROFILE that is a
#     DIRECTORY makes the append fail deterministically, with no need to
#     simulate a full disk or a quota.
#
# The third case is the positive control: a real package must still pass, so a
# gate that fails everything cannot be mistaken for a gate that works.
coverage-loop-selftest:
	@mkdir -p $(COVERAGE_DIR) $(COVERAGE_LOOP_SELFTEST_DIR)/unwritable
	@failures=0; \
	for case in "github.com/jeremyhahn/go-libsignal/pkg/nonexistent $(COVERAGE_LOOP_SELFTEST_DIR)/out fail" \
	            ". $(COVERAGE_LOOP_SELFTEST_DIR)/unwritable fail" \
	            ". $(COVERAGE_LOOP_SELFTEST_DIR)/out pass"; do \
		set -- $$case; \
		[ -d "$$2" ] || : > "$$2"; \
		if $(MAKE) -s --no-print-directory _coverage-collect \
				PROFILE="$$2" PKGS="$$1" >/dev/null 2>&1; then \
			got=pass; \
		else \
			got=fail; \
		fi; \
		if [ "$$got" = "$$3" ]; then \
			echo "ok:  pkg=$$1 profile=$$2 loop=$$got"; \
		else \
			echo "BAD: pkg=$$1 profile=$$2 loop=$$got, expected $$3"; \
			failures=$$((failures + 1)); \
		fi; \
	done; \
	rm -rf $(COVERAGE_LOOP_SELFTEST_DIR); \
	if [ "$$failures" -ne 0 ]; then \
		echo "FAIL: coverage loop self-test: $$failures case(s) behaved incorrectly"; \
		exit 1; \
	fi; \
	echo "PASS: coverage loop self-test"

coverage:
	@mkdir -p $(COVERAGE_DIR)
	@echo "mode: atomic" > $(COVERAGE_DIR)/coverage.out
	@PKGS=$$(go list ./...) || { \
		echo "FAIL: go list ./... failed -- the package list is incomplete, so any"; \
		echo "      coverage measured from it would be measured over an unknown"; \
		echo "      subset of the tree."; \
		exit 1; \
	}; \
	$(MAKE) -s --no-print-directory _coverage-collect \
		PROFILE=$(COVERAGE_DIR)/coverage.out \
		PKGS="$$(echo "$$PKGS" | grep -vE '$(COVERAGE_EXCLUDE_PATTERN)' | tr '\n' ' ')"
	@go tool cover -func=$(COVERAGE_DIR)/coverage.out
	@echo ""
	@echo "HTML report: $(COVERAGE_DIR)/coverage.html"
	@go tool cover -html=$(COVERAGE_DIR)/coverage.out -o $(COVERAGE_DIR)/coverage.html
	@echo ""
	@$(call coverage-gate,$(COVERAGE_DIR)/coverage.out,$(COVERAGE_MIN),TOTAL CODE)

# Package-specific coverage targets, named for the package PATH:
#   make coverage-pkg/cipher, make coverage-pkg/poksho
# Uses COVERAGE_MIN_<pkg> when defined (for legitimately exempt packages), otherwise
# falls back to COVERAGE_MIN (90%). Exempt packages are documented above.
$(addprefix coverage-,$(TESTABLE_PACKAGES)):
	@mkdir -p $(COVERAGE_DIR)
	@$(GOTEST) -coverprofile=$(COVERAGE_DIR)/$(subst /,_,$(subst coverage-,,$@)).out \
		-covermode=atomic ./$(subst coverage-,,$@)/...
	@go tool cover -func=$(COVERAGE_DIR)/$(subst /,_,$(subst coverage-,,$@)).out
	@echo ""
	@PKG_KEY=$$(echo "$(subst coverage-,,$@)" | tr '/' '_'); \
	PKG_MIN=$$(make -s --no-print-directory _pkg_min_$$PKG_KEY 2>/dev/null || echo $(COVERAGE_MIN)); \
	$(call coverage-gate,$(COVERAGE_DIR)/$(subst /,_,$(subst coverage-,,$@)).out,$$PKG_MIN,$(subst coverage-,,$@))

# Internal helper targets for per-package minimum lookup.
_pkg_min_pkg_groups_ratchet:
	@echo $(COVERAGE_MIN_groups_ratchet)
_pkg_min_pkg_mlkembraid:
	@echo $(COVERAGE_MIN_mlkembraid)
_pkg_min_pkg_tripleratchet:
	@echo $(COVERAGE_MIN_tripleratchet)
_pkg_min_pkg_util_crypto_secret:
	@echo $(COVERAGE_MIN_util_crypto_secret)

# Internal: runs the fail-closed gate against PROFILE with minimum MIN, so the
# self-test below exercises the real gate rather than a copy of it.
_coverage-gate:
	@$(call coverage-gate,$(PROFILE),$(MIN),gate)

# Self-test for the fail-closed coverage gate. Proves the gate FAILS when the
# percentage cannot be measured at all -- a missing or malformed profile, the
# case the previous `bc ... || echo 0` comparison waved through -- and when a
# measured percentage is below the minimum, while still passing a good one.
coverage-gate-selftest:
	@mkdir -p $(COVERAGE_SELFTEST_DIR)
	@$(GOTEST) -coverprofile=$(COVERAGE_SELFTEST_DIR)/good.out -covermode=atomic . >/dev/null
	@echo 'this is not a coverage profile' > $(COVERAGE_SELFTEST_DIR)/malformed.out
	@: > $(COVERAGE_SELFTEST_DIR)/empty.out
	@rm -f $(COVERAGE_SELFTEST_DIR)/missing.out
	@failures=0; \
	for case in "missing.out 90 fail" "malformed.out 90 fail" "empty.out 90 fail" \
	            "good.out 101 fail" "good.out 0 pass"; do \
		set -- $$case; \
		if $(MAKE) -s --no-print-directory _coverage-gate \
				PROFILE=$(COVERAGE_SELFTEST_DIR)/$$1 MIN=$$2 >/dev/null 2>&1; then \
			got=pass; \
		else \
			got=fail; \
		fi; \
		if [ "$$got" = "$$3" ]; then \
			echo "ok:  profile=$$1 min=$$2 gate=$$got"; \
		else \
			echo "BAD: profile=$$1 min=$$2 gate=$$got, expected $$3"; \
			failures=$$((failures + 1)); \
		fi; \
	done; \
	rm -rf $(COVERAGE_SELFTEST_DIR); \
	if [ "$$failures" -ne 0 ]; then \
		echo "FAIL: coverage gate self-test: $$failures case(s) behaved incorrectly"; \
		exit 1; \
	fi; \
	echo "PASS: coverage gate self-test"

# ==============================================================================
# Benchmarks
# ==============================================================================

bench:
	$(GOTEST) -bench=. -benchmem ./...

# Package-specific benchmark targets, named for the package PATH:
#   make bench-pkg/cipher, make bench-pkg/poksho
$(addprefix bench-,$(TESTABLE_PACKAGES)):
	$(GOTEST) -bench=. -benchmem -v ./$(subst bench-,,$@)/...

# ==============================================================================
# Linting & Static Analysis
# ==============================================================================

vet:
	$(GOVET) ./...

fmtcheck:
	@unformatted=$$(gofmt -l pkg/ tests/ examples/ *.go 2>/dev/null); \
	if [ -n "$$unformatted" ]; then \
		echo "The following files are not gofmt-formatted:"; \
		echo "$$unformatted"; \
		echo "Run 'gofmt -w .' to fix."; \
		exit 1; \
	fi
	@echo "gofmt: all files formatted"

# Checking the VERSION, not mere presence, is the point: an already-installed
# golangci-lint of a different version answers `which` perfectly well, so a
# presence test runs whatever the developer happens to have and the pin buys
# nothing. That is not hypothetical -- @latest is how v2.13.1 got onto this
# machine and into CI in the first place.
#
# Install on mismatch, then re-check and fail closed. The re-check should not
# be reachable, because line 68 puts $(GOBIN) -- where `go install` writes --
# at the front of PATH for every recipe. It is here so that if that ever stops
# holding, or the install fails, the target says so instead of quietly linting
# with the wrong analyser.
lint:
	@mkdir -p $(TOOLS_BIN)
	@have=$$($(GOLANGCI_LINT_BIN) version 2>/dev/null | sed -nE 's/.*has version ([0-9]+\.[0-9]+\.[0-9]+).*/v\1/p'); \
	if [ "$$have" != "$(GOLANGCI_LINT_VERSION)" ]; then \
		echo "golangci-lint $${have:-not installed}, want $(GOLANGCI_LINT_VERSION) -- installing"; \
		GOBIN=$(TOOLS_BIN) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION); \
		have=$$($(GOLANGCI_LINT_BIN) version 2>/dev/null | sed -nE 's/.*has version ([0-9]+\.[0-9]+\.[0-9]+).*/v\1/p'); \
	fi; \
	if [ "$$have" != "$(GOLANGCI_LINT_VERSION)" ]; then \
		echo "FAIL: $(GOLANGCI_LINT_BIN) resolves to $${have:-nothing} after"; \
		echo "      installing $(GOLANGCI_LINT_VERSION). Linting with a version CI does"; \
		echo "      not run tells you nothing, so this fails rather than proceeding."; \
		exit 1; \
	fi
	@$(MAKE) --no-print-directory _lint-retry

# golangci-lint takes a global lock, and $(GOBIN) is shared across every agent
# lane on this host. A concurrent run exits 3 with "parallel golangci-lint is
# running" -- which reads exactly like a lint failure, and `make ci` includes
# lint, so the phantom gets debugged. Observed 3 consecutive times on
# 2026-08-21 before the 4th attempt worked.
#
# Retry ONLY that signature. A real finding must fail on the first attempt,
# because a target that retries failures hides them. Split out of `lint` so
# lint-retry-selftest can drive it with a stub $(LINT_CMD); the contract it
# holds to is the four cases that self-test asserts.
_lint-retry:
	@attempt=1; \
	while :; do \
		out=$$($(LINT_CMD) 2>&1); status=$$?; \
		case "$$out" in \
			*"parallel golangci-lint is running"*) ;; \
			*) printf '%s\n' "$$out"; exit $$status;; \
		esac; \
		if [ "$$attempt" -ge $(LINT_RETRY_MAX) ]; then \
			printf '%s\n' "$$out"; \
			echo "FAIL: another golangci-lint held the lock for $(LINT_RETRY_MAX) attempts."; \
			echo "      This is host contention, not a finding -- retry later."; \
			[ "$$status" -ne 0 ] || status=1; \
			exit $$status; \
		fi; \
		echo "golangci-lint: another run holds the lock (attempt $$attempt) -- contention, not a finding; retrying"; \
		attempt=$$((attempt + 1)); \
		sleep $(LINT_RETRY_DELAY); \
	done

# Self-test for the retry contract Codex raised on #33: an untested retry loop
# can start retrying genuine findings, or report success after exhausting its
# attempts, with nothing failing. Four cases, each driven by a stub linter
# passed as $(LINT_CMD) -- NOT planted on PATH, which $(GOBIN) would shadow.
# `:=` rather than `?=` on those variables so a stray environment variable
# cannot redirect what a real `make lint` executes; a command-line override,
# which is how this target passes its stubs, still wins.
#
# LINT_RETRY_DELAY=0 keeps the exhaustion case from sleeping through its own
# retries; the delay is not part of the contract being asserted.
lint-retry-selftest:
	@dir=$$(mktemp -d); trap 'rm -rf "$$dir"' EXIT; failures=0; \
	printf '#!/bin/sh\nn=$$(cat "$$1"); n=$$((n + 1)); echo "$$n" > "$$1"\n' > $$dir/count.sh; \
	chmod +x $$dir/count.sh; \
	printf '#!/bin/sh\n"%s" "%s"\nif [ "$$(cat "%s")" -lt 3 ]; then\n  echo "ERRO Running error: context loading failed: parallel golangci-lint is running"\n  exit 3\nfi\necho "0 issues."\n' \
		$$dir/count.sh $$dir/n1 $$dir/n1 > $$dir/recovers; \
	printf '#!/bin/sh\n"%s" "%s"\necho "pkg/foo.go:12:2: undefined: bar (typecheck)"\nexit 1\n' \
		$$dir/count.sh $$dir/n2 > $$dir/finding; \
	printf '#!/bin/sh\n"%s" "%s"\necho "ERRO Running error: context loading failed: parallel golangci-lint is running"\nexit 3\n' \
		$$dir/count.sh $$dir/n3 > $$dir/stuck; \
	printf '#!/bin/sh\necho "ERRO parallel golangci-lint is running"\nexit 0\n' > $$dir/stuck0; \
	chmod +x $$dir/recovers $$dir/finding $$dir/stuck $$dir/stuck0; \
	for f in n1 n2 n3; do echo 0 > $$dir/$$f; done; \
	out=$$($(MAKE) --no-print-directory _lint-retry LINT_CMD=$$dir/recovers LINT_RETRY_DELAY=0 2>&1); st=$$?; \
	if [ "$$st" -eq 0 ] && [ "$$(cat $$dir/n1)" -eq 3 ]; then \
		echo "ok:  a lock failure is retried and recovers (3 attempts, exit 0)"; \
	else \
		echo "BAD: lock failure did not recover: exit $$st after $$(cat $$dir/n1) attempt(s)"; \
		printf '%s\n' "$$out"; failures=$$((failures + 1)); \
	fi; \
	out=$$($(MAKE) --no-print-directory _lint-retry LINT_CMD=$$dir/finding LINT_RETRY_DELAY=0 2>&1); st=$$?; \
	if [ "$$st" -ne 0 ] && [ "$$(cat $$dir/n2)" -eq 1 ] && case "$$out" in *"undefined: bar"*) true;; *) false;; esac; then \
		echo "ok:  a genuine finding runs once, keeps its status and its output"; \
	else \
		echo "BAD: genuine finding: exit $$st after $$(cat $$dir/n2) attempt(s), output:"; \
		printf '%s\n' "$$out"; failures=$$((failures + 1)); \
	fi; \
	out=$$($(MAKE) --no-print-directory _lint-retry LINT_CMD=$$dir/stuck LINT_RETRY_DELAY=0 2>&1); st=$$?; \
	if [ "$$st" -ne 0 ] && [ "$$(cat $$dir/n3)" -eq $(LINT_RETRY_MAX) ]; then \
		echo "ok:  a persistent lock stops after $(LINT_RETRY_MAX) attempts, nonzero"; \
	else \
		echo "BAD: persistent lock: exit $$st after $$(cat $$dir/n3) attempt(s)"; \
		printf '%s\n' "$$out"; failures=$$((failures + 1)); \
	fi; \
	$(MAKE) --no-print-directory _lint-retry LINT_CMD=$$dir/stuck0 LINT_RETRY_DELAY=0 >/dev/null 2>&1; st=$$?; \
	if [ "$$st" -ne 0 ]; then \
		echo "ok:  exhaustion fails closed even when the linter exited 0"; \
	else \
		echo "BAD: exhausted retries returned success because the linter exited 0"; \
		failures=$$((failures + 1)); \
	fi; \
	if [ "$$failures" -ne 0 ]; then \
		echo "FAIL: lint-retry self-test: $$failures check(s) failed"; \
		exit 1; \
	fi; \
	echo "PASS: lint-retry self-test"

# ==============================================================================
# Security Scanning
# ==============================================================================

# devops.md §8: every -exclude rule carries a written justification beside it.
#
#   G115  integer overflow conversion (int -> uint8/uint16/uint32).
#         206 findings, and they are the rule's known false-positive mode
#         rather than defects. A wire-format library length-prefixes almost
#         every field, so `byte(len(b))` and `uint32(len(b))` appear on nearly
#         every serializer; in each case the length is already bounded by a
#         checked limit upstream (frame caps, MAX_* consts mirrored from Rust
#         libsignal) that gosec's per-expression analysis cannot see. The
#         conversions that are genuinely unbounded are guarded explicitly —
#         see PaddedLength's saturating clamp in pkg/backup/backup.go and its
#         regression tests. Narrowing this exclusion means annotating each of
#         the 206 sites with #nosec plus the bound it relies on; that is worth
#         doing and is tracked for the v1.0 audit pass, not achievable as a
#         side effect of a CI fix.
GOSEC_EXCLUDE := G115

gosec:
	@which gosec > /dev/null 2>&1 || \
		(echo "Installing gosec..." && \
		go install github.com/securego/gosec/v2/cmd/gosec@latest)
	gosec -fmt=text -severity=medium -exclude=$(GOSEC_EXCLUDE) ./...

govulncheck:
	@which govulncheck > /dev/null 2>&1 || \
		(echo "Installing govulncheck..." && \
		go install golang.org/x/vuln/cmd/govulncheck@latest)
	govulncheck ./...

# Checking the VERSION, not mere presence -- the same defect fixed for
# golangci-lint in #17, on the tool that actually reports the SA findings.
# SA1019 and SA6001 are what took main red on 2026-08-20, so an analyser nobody
# chose can both miss findings and invent them.
#
# Install on mismatch, then re-check and fail closed. The re-check should not be
# reachable, because $(GOBIN) -- where `go install` writes -- is at the front of
# PATH for every recipe. It is here so that if that stops holding, the target
# says so instead of quietly analysing with the wrong version.
# Two targets because there are two policies, and collapsing them loses one.
#
#   staticcheck        pinned, reproducible -- what a local run and `make
#                      security` use, so a neighbour's install cannot change
#                      the answer.
#   staticcheck-latest DISCOVERY -- what CI's Security Scan runs. Pinning this
#                      one too would mean no new SA rule is ever found, and
#                      SA1019/SA6001 taking main red on 2026-08-20 is what that
#                      would have cost.
#
# The pinned target ignores whatever is in $(GOBIN), so a workflow that installs
# @latest there and then calls `make staticcheck` silently gets the pin -- the
# discovery gate reporting success while running the version it was meant to
# improve on. That is why CI calls this target by name.
#
# It installs into its own directory rather than $(GOBIN) for the same reason
# the pinned one does: this repo should not decide which staticcheck other lanes
# get. On a clean CI runner that costs one download.
staticcheck-latest:
	@mkdir -p $(dir $(STATICCHECK_LATEST_BIN))
	@GOBIN=$(dir $(STATICCHECK_LATEST_BIN)) go install honnef.co/go/tools/cmd/staticcheck@latest; \
	have=$$($(STATICCHECK_LATEST_BIN) -version 2>/dev/null | sed -nE 's/.*\(([0-9]+\.[0-9]+\.[0-9]+)\).*/v\1/p'); \
	if [ -z "$$have" ]; then \
		echo "FAIL: staticcheck@latest did not install to $(STATICCHECK_LATEST_BIN)"; \
		exit 1; \
	fi; \
	if [ "$$have" != "$(STATICCHECK_VERSION)" ]; then \
		echo "NOTE: staticcheck@latest is $$have, the pin is $(STATICCHECK_VERSION)."; \
		echo "      If this job reports findings the pinned local run does not,"; \
		echo "      bump STATICCHECK_VERSION -- that is the intended workflow."; \
	fi; \
	echo "staticcheck $$have (latest, $(STATICCHECK_LATEST_BIN))"; \
	$(STATICCHECK_LATEST_BIN) ./...

staticcheck:
	@mkdir -p $(TOOLS_BIN)
	@have=$$($(STATICCHECK_BIN) -version 2>/dev/null | sed -nE 's/.*\(([0-9]+\.[0-9]+\.[0-9]+)\).*/v\1/p'); \
	if [ "$$have" != "$(STATICCHECK_VERSION)" ]; then \
		echo "staticcheck $${have:-not installed}, want $(STATICCHECK_VERSION) -- installing"; \
		GOBIN=$(TOOLS_BIN) go install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION); \
		have=$$($(STATICCHECK_BIN) -version 2>/dev/null | sed -nE 's/.*\(([0-9]+\.[0-9]+\.[0-9]+)\).*/v\1/p'); \
	fi; \
	if [ "$$have" != "$(STATICCHECK_VERSION)" ]; then \
		echo "FAIL: $(STATICCHECK_BIN) resolves to $${have:-nothing} after installing"; \
		echo "      $(STATICCHECK_VERSION). Analysing with a version CI does not run"; \
		echo "      tells you nothing, so this fails rather than proceeding."; \
		exit 1; \
	fi; \
	echo "staticcheck $$have ($(STATICCHECK_BIN))"; \
	$(STATICCHECK_BIN) ./...

errcheck:
	@which errcheck > /dev/null 2>&1 || \
		(echo "Installing errcheck..." && \
		go install github.com/kisielk/errcheck@latest)
	errcheck ./...

nilcheck:
	@which nilaway > /dev/null 2>&1 || \
		(echo "Installing nilaway..." && \
		go install go.uber.org/nilaway/cmd/nilaway@latest)
	nilaway ./... || true

modverify:
	go mod verify

# Filesystem CVE/secret scan, gated on CRITICAL/HIGH. tests/, examples/ and
# bench/ are skipped: none of them ship to a consumer of the library, and
# tests/interop/rust carries the upstream Rust reference crate purely to diff
# wire bytes against.
trivy:
	@command -v trivy >/dev/null 2>&1 || { \
		echo "trivy not installed - skipping filesystem scan (see https://trivy.dev/latest/getting-started/installation/)"; \
		exit 0; \
	}; \
	trivy fs --scanners vuln,secret --severity CRITICAL,HIGH --exit-code 1 --skip-dirs tests,examples,bench .

# Image scan of the only container this repo builds: the Rust<->Go interop
# test harness (`make interop-docker`), which is never pushed to a registry.
#
# NOT a prerequisite of `security`, and deliberately so. tests/interop/rust/
# Cargo.toml carries path dependencies on ../../../../libsignal/rust/{protocol,
# zkgroup,core} — a sibling checkout of upstream Rust libsignal that the
# Dockerfile never provides, so the rust-builder stage fails at `cargo build`
# with "failed to read /libsignal/rust/core/Cargo.toml". That is a pre-existing
# defect in the harness Dockerfile, not a security finding, and chaining it
# into `security` would give this repo a gate that fails for an unrelated
# reason. Wire it into `security` (and add the matching CI job) once the
# Dockerfile clones upstream at /RUST_REV the way the conformance-fixtures CI
# job already does.
#
# Two scoping decisions, both deliberate:
#
#   --ignore-unfixed  The final stage is golang:<stable>-bookworm, so its
#                     Debian package set is upstream's. A CVE with no released
#                     fix cannot be actioned by rebuilding and would pin this
#                     gate permanently red; a CVE that HAS a fix means the
#                     base is stale, which is a real finding.
#   --skip-dirs       usr/local/go and go/pkg/mod are the toolchain and module
#                     cache the image carries so it can run `go test` inside.
#                     Their contents are upstream release artifacts, not
#                     go-libsignal code.
#
# The Go module tree is gated unconditionally by `make trivy` and govulncheck.
trivy-image:
	@command -v docker >/dev/null 2>&1 || { echo "docker not installed - skipping image scan"; exit 0; }; \
	command -v trivy >/dev/null 2>&1 || { echo "trivy not installed - skipping image scan"; exit 0; }; \
	docker build -f tests/interop/Dockerfile -t libsignal-interop:security . && \
	trivy image --scanners vuln,secret --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1 \
		--skip-dirs usr/local/go --skip-dirs go/pkg/mod libsignal-interop:security

# The full devops.md §8 suite. See trivy-image above for why the image scan is
# not chained in yet.
security: gosec govulncheck staticcheck modverify trivy

# ==============================================================================
# CI
# ==============================================================================

examples-build:
	GOWORK=off go build ./examples/...

ci: fmtcheck vet lint security test test-proptest coverage examples-build

# ==============================================================================
# Cleanup
# ==============================================================================

clean:
	rm -rf $(COVERAGE_DIR)
	rm -f *.log *.test *.out *.prof
	go clean -testcache -cache

# ==============================================================================
# Help
# ==============================================================================

help:
	@echo "go-libsignal Makefile targets:"
	@echo ""
	@echo "  Build:"
	@echo "    make build              - Build all packages"
	@echo "    make all                - Vet, test, and build"
	@echo ""
	@echo "  Testing:"
	@echo "    make test               - Run all unit tests"
	@echo "    make test-verbose       - Run all unit tests with verbose output"
	@echo "    make test-pkg/NAME      - Run tests for one package (e.g. test-pkg/cipher)"
	@echo "    make test-proptest      - Run the pkg/session property tests (own CI job)"
	@echo "    make test-interop         - Run Phase 3a Rust<->Go interop fixture tests"
	@echo "    make interop-live-build   - Build Rust interop binaries (interop_runner + wire_emitter)"
	@echo "    make interop-live         - Build and run all Phase 3b live interop tests"
	@echo "    make interop-live-session - Run only session round-trip live tests"
	@echo "    make interop-live-sealed  - Run only sealed sender live tests"
	@echo "    make interop-live-group   - Run only SenderKey live tests"
	@echo "    make interop-live-backup  - Run only backup frame live tests"
	@echo "    make interop-docker       - Build Docker image and run live tests in container"
	@echo ""
	@echo "  Coverage:"
	@echo "    make coverage           - Generate coverage report for all packages"
	@echo "    make coverage-pkg/NAME  - Coverage for one package (e.g. coverage-pkg/cipher)"
	@echo "    make coverage-gate-selftest - Verify the coverage threshold fails closed"
	@echo "    make coverage-loop-selftest - Verify the per-package loop fails closed"
	@echo ""
	@echo "  Benchmarks:"
	@echo "    make bench              - Run all benchmarks"
	@echo "    make bench-pkg/NAME     - Benchmarks for one package (e.g. bench-pkg/cipher)"
	@echo ""
	@echo "  Quality:"
	@echo "    make vet                - Run go vet"
	@echo "    make lint               - Run golangci-lint"
	@echo "    make lint-retry-selftest - Verify lint retries contention, not findings"
	@echo "    make lint-pin-selftest  - Verify the golangci-lint pin cannot be raced"
	@echo ""
	@echo "  Security:"
	@echo "    make security           - Full devops.md §8 suite (gosec, govulncheck, staticcheck, go mod verify, trivy fs)"
	@echo "    make gosec              - Run gosec (common Go security issues)"
	@echo "    make govulncheck        - Run govulncheck (known dependency vulnerabilities)"
	@echo "    make staticcheck        - Run staticcheck (advanced static analysis)"
	@echo "    make modverify          - Verify module integrity against go.sum"
	@echo "    make trivy              - Filesystem CVE/secret scan (CRITICAL/HIGH gate)"
	@echo "    make trivy-image        - Scan the interop harness image (see Makefile note)"
	@echo "    make errcheck           - Run errcheck (unchecked error returns)"
	@echo "    make nilcheck           - Run nilaway (nil dereference analysis, non-blocking)"
	@echo ""
	@echo "  FIPS:"
	@echo "    make fips               - FIPS 140-3 gate: build + unit tests under GODEBUG=fips140=only"
	@echo "    make fips-build         - Build all packages under GODEBUG=fips140=only"
	@echo "    make fips-test          - Run unit tests under GODEBUG=fips140=only (see docs/FIPS.md)"
	@echo ""
	@echo "  CI:"
	@echo "    make ci                 - Run full CI pipeline: vet lint security test coverage examples-build"
	@echo ""
	@echo "  Examples:"
	@echo "    make examples-build     - Compile all runnable examples under examples/"
	@echo ""
	@echo "  Maintenance:"
	@echo "    make clean              - Clean coverage files and test cache"
	@echo "    make help               - Show this help"

SUBMODULE_TAGS := 

# ---- dependency-resolution.md targets (2026-08-13 cutover) ----
# SUBMODULE_TAGS lists nested modules tagged in lockstep with the root
# (release-versioning.md P2). deps-latest runs before compiling in a
# consumer repo; release-alpha publishes this repo's next -alpha tag to dev.
# deps-latest picks the highest tag INCLUDING -alpha prereleases — bare
# 'go get @latest' ignores prereleases and would downgrade to legacy v0.0.0.

.PHONY: release-alpha deps-latest

release-alpha:
	@V=$$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || echo v0.0.0-alpha); \
	NEXT=$$(echo $$V | awk -F'[.-]' '{printf "v%s.%s.%d-alpha", substr($$1,2), $$2, $$3+1}'); \
	echo $${NEXT#v} > VERSION && git add VERSION && git commit -q -m "chore(release): $$NEXT" || true; \
	git tag $$NEXT; \
	for s in $(SUBMODULE_TAGS); do git tag "$$s/$$NEXT"; done; \
	git push dev HEAD --tags && echo "Tagged $$NEXT"

deps-latest:
	@GOWORK=off sh -c ' \
	SELF=$$(go list -m); \
	for m in $$(go list -m -f "{{if not .Indirect}}{{.Path}}{{end}}" all 2>/dev/null | grep "^github.com/jeremyhahn/" | grep -vx "$$SELF"); do \
	  case "$$(go list -m -f "{{if .Replace}}{{.Replace.Path}}{{end}}" "$$m" 2>/dev/null)" in .*|/*) continue;; esac; \
	  V=$$(go list -m -versions "$$m" 2>/dev/null | tr " " "\n" | tail -1); \
	  if [ -n "$$V" ] && [ "$$V" != "$$m" ]; then go get "$$m@$$V" || exit 1; fi; \
	done; go mod tidy'
