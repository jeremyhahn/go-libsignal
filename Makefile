# Makefile for go-libsignal
# Signal Protocol library for Go

# ==============================================================================
# Configuration
# ==============================================================================

MODULE := github.com/jeremyhahn/go-libsignal
# Not VERSION: release-alpha takes the tag as VERSION=vX.Y.Z-alpha and a definition here would shadow it.
BUILD_VERSION := $(shell cat VERSION 2>/dev/null || echo "0.0.0")
# Per-test-binary timeout; it also governs the FIPS gate, so raising it relaxes that gate too.
GOTEST_TIMEOUT := 900s
GOTEST := go test -timeout=$(GOTEST_TIMEOUT)
GOVET := go vet
GOBUILD := go build

# Pinned to upstream latest and kept equal to the Lint job pin in ci.yml (lint-pin-selftest checks); installed to a repo-local directory.
GOLANGCI_LINT_VERSION := v2.14.0

# Pinned staticcheck, installed and run from one repo-local path; CI's Security Scan runs staticcheck-latest for discovery.
STATICCHECK_VERSION := v0.8.1
COVERAGE_DIR := coverage
COVERAGE_SELFTEST_DIR := $(COVERAGE_DIR)/gate-selftest
COVERAGE_LOOP_SELFTEST_DIR := $(COVERAGE_DIR)/loop-selftest
COVERAGE_MIN := 90

# Per-package coverage minimums where locked-memory OOM guards and dead branches cannot be reached in unit tests; all others use COVERAGE_MIN.
COVERAGE_MIN_groups_ratchet := 87
COVERAGE_MIN_mlkembraid := 87
COVERAGE_MIN_tripleratchet := 87
COVERAGE_MIN_util_crypto_secret := 95
GOBIN := $(shell go env GOPATH)/bin

# Pinned analysers live in a repo-local directory so the checked and the executed binary are the same path.
TOOLS_BIN := $(CURDIR)/.tools/bin

# gosec and staticcheck build from one committed tool module that raises golang.org/x/tools for the current Go toolchain.
TOOLS_MODULE := tools
CI_WORKFLOW := .github/workflows/ci.yml
STATICCHECK_BIN := $(TOOLS_BIN)/staticcheck
STATICCHECK_LATEST_BIN := $(TOOLS_BIN)-latest/staticcheck
GOLANGCI_LINT_BIN := $(TOOLS_BIN)/golangci-lint

# actionlint validates the workflows (devops.md §4, the `make lint` row).
# Pinned to upstream latest; reads .github/actionlint.yaml when present.
ACTIONLINT_VERSION := v1.7.12
ACTIONLINT_BIN := $(TOOLS_BIN)/actionlint

# Lint runs through $(LINT_CMD) so lint-retry-selftest can substitute a stub.
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
	vet lint actionlint _lint-retry lint-retry-selftest lint-pin-selftest \
	clean coverage coverage-gate-selftest _coverage-gate help \
	coverage-loop-selftest _coverage-collect \
	ci security gosec govulncheck staticcheck errcheck nilcheck \
	modverify trivy trivy-image staticcheck-latest staticcheck-selftest \
	fips fips-build fips-test \
	test-slow-session test-proptest test-proptest-selftest examples-build bench \
	_pkg_min_pkg_groups_ratchet _pkg_min_pkg_mlkembraid \
	_pkg_min_pkg_tripleratchet _pkg_min_pkg_util_crypto_secret

# The generated per-package targets are actions, never files, so they are .PHONY.
.PHONY: $(addprefix test-,$(TESTABLE_PACKAGES)) \
	$(addprefix coverage-,$(TESTABLE_PACKAGES)) \
	$(addprefix bench-,$(TESTABLE_PACKAGES))

# ==============================================================================
# Build
# ==============================================================================

all: vet test build

build:
	@echo "Building go-libsignal v$(BUILD_VERSION)"
	$(GOBUILD) ./...

# ==============================================================================
# Testing
# ==============================================================================

test:
	$(GOTEST) -race ./...

test-verbose:
	$(GOTEST) -race -v ./...

# No | tee: without pipefail the pipeline would report tee's status.
integration-test:
	$(GOTEST) -race -v ./tests/...

# Slow tests (build tag slow), e.g. the 25,001-message chain-jump limit; about 60-120 s.
test-slow-session:
	GOWORK=off $(GOTEST) -race -count=1 -tags=slow -run TestRust_ChainJumpOverLimit ./pkg/session/...

# Property tests (build tag proptest) with their own 2400s budget, below the job cap; the expected test count comes from the source so a dropped tag fails.
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

# Self-test for test-proptest: static timeout checks plus a fail-closed run on a file with no property tests.
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
# Self-test for pinned tools: the recipe runs and installs the pinned path, which lies outside $(GOBIN).
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
	$(call assert_pinned,staticcheck,staticcheck,$(STATICCHECK_BIN),$(STATICCHECK_BIN) ./...,cd $(TOOLS_MODULE) && GOBIN=$(TOOLS_BIN) go install honnef.co/go/tools/cmd/staticcheck) \
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

# The pinned-tool assertions for golangci-lint; the expected invocation is spelled from $(GOLANGCI_LINT_BIN), not $(LINT_CMD).
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

# Verify every fixture against MANIFEST.toml; with LIBSIGNAL_UPSTREAM set, also diff against the upstream tree at /RUST_REV.
interop-fixtures-check:
	tests/interop/scripts/check_fixtures.sh

# Refresh fixtures from an upstream checkout; then regenerate MANIFEST.toml sha256 entries and bump /RUST_REV.
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

# fips140=only makes non-approved operations fail; the fips140only tag excludes the exempt tests listed in docs/FIPS.md.
FIPS_ENV := GOFIPS140=latest GODEBUG=fips140=only

fips: fips-build fips-test

fips-build:
	$(FIPS_ENV) $(GOBUILD) ./...

fips-test:
	$(FIPS_ENV) $(GOTEST) -count=1 -tags fips140only ./...

# ==============================================================================
# Code Coverage
# ==============================================================================

# Fail-closed coverage gate: $(1) profile, $(2) minimum, $(3) label; an unmeasurable percentage fails.
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

# Per-package coverage collection over PKGS into PROFILE; fails if any package does not complete.
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

# Self-test for the collection loop: an unloadable package and an unwritable profile must fail, a real package must pass.
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

# Per-package coverage targets (make coverage-pkg/cipher); COVERAGE_MIN_<pkg> overrides COVERAGE_MIN.
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

# Runs the coverage gate against PROFILE with minimum MIN for the self-test.
_coverage-gate:
	@$(call coverage-gate,$(PROFILE),$(MIN),gate)

# Self-test: the gate fails on a missing or malformed profile and below the minimum, and passes a good one.
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

# Check the pinned version, install on mismatch, then re-check and fail closed.
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
	@$(MAKE) --no-print-directory actionlint

# Pinned actionlint: the repo-local copy, or one on PATH at exactly the pin; otherwise install, then fail closed.
actionlint:
	@bin=$(ACTIONLINT_BIN); \
	have=$$($$bin -version 2>/dev/null | head -n 1); \
	if [ "$$have" != "$(ACTIONLINT_VERSION)" ]; then \
		bin=$$(command -v actionlint); \
		have=$$([ -n "$$bin" ] && $$bin -version 2>/dev/null | head -n 1); \
	fi; \
	if [ "$$have" != "$(ACTIONLINT_VERSION)" ]; then \
		echo "actionlint $${have:-not installed}, want $(ACTIONLINT_VERSION) -- installing"; \
		mkdir -p $(TOOLS_BIN); \
		GOBIN=$(TOOLS_BIN) go install github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION); \
		bin=$(ACTIONLINT_BIN); \
		have=$$($$bin -version 2>/dev/null | head -n 1); \
	fi; \
	if [ "$$have" != "$(ACTIONLINT_VERSION)" ]; then \
		echo "FAIL: no actionlint $(ACTIONLINT_VERSION) after installing it; the workflows"; \
		echo "      were not validated, so this fails rather than passing."; \
		exit 1; \
	fi; \
	$$bin && echo "actionlint: workflows clean"

# Retry only golangci-lint's "parallel golangci-lint is running" exit; a real finding fails on the first attempt.
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

# Self-test for the lint retry contract with stub linters passed as $(LINT_CMD); LINT_RETRY_DELAY=0 skips the sleeps.
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

# G115 excluded: length conversions are bounded by checked limits gosec cannot see; unbounded ones are clamped explicitly.
GOSEC_EXCLUDE := G115

# gosec is built from the committed tool module and verified from the binary's build info.
GOSEC_VERSION := v2.29.0
GOSEC_XTOOLS_VERSION := v0.51.0
GOSEC_MODULE := $(TOOLS_MODULE)
GOSEC_BIN := $(TOOLS_BIN)/gosec
GOSEC_PINNED = ( [ -x $(GOSEC_BIN) ] && \
	go version -m $(GOSEC_BIN) > $(TOOLS_BIN)/.gosec-buildinfo 2>/dev/null && \
	grep -qE '^[[:space:]]+mod[[:space:]]+github.com/securego/gosec/v2[[:space:]]+$(GOSEC_VERSION)[[:space:]]' $(TOOLS_BIN)/.gosec-buildinfo && \
	grep -qE '^[[:space:]]+dep[[:space:]]+golang.org/x/tools[[:space:]]+$(GOSEC_XTOOLS_VERSION)[[:space:]]' $(TOOLS_BIN)/.gosec-buildinfo )

gosec:
	@mkdir -p $(TOOLS_BIN)
	@if ! $(GOSEC_PINNED); then \
		echo "gosec $(GOSEC_VERSION) built against x/tools $(GOSEC_XTOOLS_VERSION) not at $(GOSEC_BIN) -- installing"; \
		(cd $(GOSEC_MODULE) && GOBIN=$(TOOLS_BIN) go install tool) || true; \
	fi
	@if ! $(GOSEC_PINNED); then \
		echo "FAIL: $(GOSEC_BIN) is not gosec $(GOSEC_VERSION) built against"; \
		echo "      x/tools $(GOSEC_XTOOLS_VERSION), and installing it from $(GOSEC_MODULE) did not"; \
		echo "      produce that build. Scanning with another gosec tells you nothing"; \
		echo "      about what CI runs under this Go, so this fails rather than proceeding."; \
		exit 1; \
	fi
	$(GOSEC_BIN) -concurrency 4 -fmt=text -severity=medium -exclude=$(GOSEC_EXCLUDE) ./...

govulncheck:
	@which govulncheck > /dev/null 2>&1 || \
		(echo "Installing govulncheck..." && \
		go install golang.org/x/vuln/cmd/govulncheck@latest)
	govulncheck ./...

# staticcheck is pinned and reproducible; staticcheck-latest is CI discovery, built with x/tools@latest into its own directory.
staticcheck-latest:
	@mkdir -p $(dir $(STATICCHECK_LATEST_BIN))
	@dir=$$(mktemp -d) && \
	( cd "$$dir" && go mod init staticcheck-latest && \
	  go get honnef.co/go/tools/cmd/staticcheck@latest golang.org/x/tools@latest && \
	  GOBIN=$(dir $(STATICCHECK_LATEST_BIN)) go install honnef.co/go/tools/cmd/staticcheck ) \
	  || echo "staticcheck@latest build failed (go output above)"; \
	rm -rf "$$dir"; \
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
		(cd $(TOOLS_MODULE) && GOBIN=$(TOOLS_BIN) go install honnef.co/go/tools/cmd/staticcheck) || true; \
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

# Filesystem CVE and secret scan gated on CRITICAL/HIGH, skipping tests/, examples/ and bench/; a missing trivy fails.
TRIVY_INSTALL_HINT := install trivy: https://trivy.dev/latest/getting-started/installation/
trivy:
	@command -v trivy >/dev/null 2>&1 || { \
		echo "FAIL: trivy not installed, so the filesystem scan cannot run ($(TRIVY_INSTALL_HINT))"; \
		exit 1; \
	}; \
	trivy fs --scanners vuln,secret --severity CRITICAL,HIGH --exit-code 1 --skip-dirs tests,examples,bench .

# Image scan of the interop harness image; not part of security until its Dockerfile provides the upstream checkout.
trivy-image:
	@command -v docker >/dev/null 2>&1 || { echo "FAIL: docker not installed, so the image cannot be built and scanned"; exit 1; }; \
	command -v trivy >/dev/null 2>&1 || { echo "FAIL: trivy not installed, so the image scan cannot run ($(TRIVY_INSTALL_HINT))"; exit 1; }; \
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
	@echo "    make lint               - Run golangci-lint and actionlint"
	@echo "    make actionlint         - Validate the GitHub/Gitea workflows (pinned actionlint)"
	@echo "    make lint-retry-selftest - Verify lint retries contention, not findings"
	@echo "    make lint-pin-selftest  - Verify the golangci-lint pin cannot be raced"
	@echo ""
	@echo "  Security:"
	@echo "    make security           - Full devops.md §8 suite (gosec, govulncheck, staticcheck, go mod verify, trivy fs)"
	@echo "    make gosec              - Run pinned gosec (common Go security issues; built from tools/)"
	@echo "    make govulncheck        - Run govulncheck (known dependency vulnerabilities)"
	@echo "    make staticcheck        - Run pinned staticcheck (advanced static analysis; built from tools/)"
	@echo "    make staticcheck-latest - Run staticcheck@latest on x/tools@latest (discovery; needs network)"
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
	@echo "  Release:"
	@echo "    make release-alpha VERSION=vX.Y.Z-alpha - Cut and push a signed alpha tag from main to dev"
	@echo "    make test-release-alpha - Run the release-alpha template regression test"
	@echo ""
	@echo "  Maintenance:"
	@echo "    make clean              - Clean coverage files and test cache"
	@echo "    make help               - Show this help"

# release-alpha (handbook template); cut with make release-alpha VERSION=vX.Y.Z-alpha from main.
AGENT_GIT ?= agent-git.sh
REPO_NAME ?= go-libsignal
RELEASE_REMOTE ?= dev
include make/release-alpha.mk

# Runs the template's regression test against a throwaway bare remote.
test-release-alpha:
	bash make/testdata/release-alpha-tests.sh

# deps-latest picks the highest tag including -alpha prereleases.

.PHONY: release-alpha test-release-alpha deps-latest

deps-latest:
	@GOWORK=off sh -c ' \
	SELF=$$(go list -m); \
	for m in $$(go list -m -f "{{if not .Indirect}}{{.Path}}{{end}}" all 2>/dev/null | grep "^github.com/jeremyhahn/" | grep -vx "$$SELF"); do \
	  case "$$(go list -m -f "{{if .Replace}}{{.Replace.Path}}{{end}}" "$$m" 2>/dev/null)" in .*|/*) continue;; esac; \
	  V=$$(go list -m -versions "$$m" 2>/dev/null | tr " " "\n" | tail -1); \
	  if [ -n "$$V" ] && [ "$$V" != "$$m" ]; then go get "$$m@$$V" || exit 1; fi; \
	done; go mod tidy'
