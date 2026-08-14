# Makefile for go-libsignal
# Signal Protocol library for Go

# ==============================================================================
# Configuration
# ==============================================================================

MODULE := github.com/jeremyhahn/go-libsignal
VERSION := $(shell cat VERSION 2>/dev/null || echo "0.0.0")
GOTEST := go test
GOVET := go vet
GOBUILD := go build
COVERAGE_DIR := coverage
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
	vet lint clean coverage help \
	ci security gosec govulncheck staticcheck errcheck nilcheck \
	modverify trivy trivy-image \
	test-slow-session examples-build

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

integration-test:
	$(GOTEST) -race -v ./tests/... 2>&1 | tee integration-test.log

# Slow tests: marked //go:build slow; excluded from make test.
# test_chain_jump_over_limit (rust/protocol/tests/session.rs:245):
#   Alice sends 25,001 messages without Bob decrypting, then sends one more.
#   Bob's decrypt must fail because the chain-key advance exceeds 25,000.
#   Expected runtime: ~60-120 s.
test-slow-session:
	GOWORK=off $(GOTEST) -race -count=1 -tags=slow -run TestRust_ChainJumpOverLimit ./pkg/session/...

test-interop:
	GOWORK=off go test -race -v ./tests/interop/...

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
	GOWORK=off go test -tags=interop_live -race -v ./tests/interop/live/...

interop-live-session:
	LIBSIGNAL_INTEROP_LIVE_BIN=$(CURDIR)/tests/interop/rust/target/release/interop_runner \
	GOWORK=off go test -tags=interop_live -race -v -run TestLiveInterop_SessionRoundTrip \
		./tests/interop/live/...

interop-live-sealed:
	LIBSIGNAL_INTEROP_LIVE_BIN=$(CURDIR)/tests/interop/rust/target/release/interop_runner \
	GOWORK=off go test -tags=interop_live -race -v -run TestLiveInterop_SealedSender \
		./tests/interop/live/...

interop-live-group:
	LIBSIGNAL_INTEROP_LIVE_BIN=$(CURDIR)/tests/interop/rust/target/release/interop_runner \
	GOWORK=off go test -tags=interop_live -race -v -run TestLiveInterop_SenderKey \
		./tests/interop/live/...

interop-live-backup:
	LIBSIGNAL_INTEROP_LIVE_BIN=$(CURDIR)/tests/interop/rust/target/release/interop_runner \
	GOWORK=off go test -tags=interop_live -race -v -run TestLiveInterop_Backup \
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

# Package-specific test targets: make test-cipher, make test-poksho, etc.
$(addprefix test-,$(TESTABLE_PACKAGES)):
	$(GOTEST) -v ./$(subst test-,,$@)/...

# ==============================================================================
# Code Coverage
# ==============================================================================

coverage:
	@mkdir -p $(COVERAGE_DIR)
	@echo "mode: atomic" > $(COVERAGE_DIR)/coverage.out
	@PKGS=$$(go list ./... 2>/dev/null | grep -vE '$(COVERAGE_EXCLUDE_PATTERN)'); \
	for pkg in $$PKGS; do \
		$(GOTEST) -coverprofile=$(COVERAGE_DIR)/pkg.out -covermode=atomic "$$pkg" 2>/dev/null; \
		if [ -f $(COVERAGE_DIR)/pkg.out ]; then \
			tail -n +2 $(COVERAGE_DIR)/pkg.out >> $(COVERAGE_DIR)/coverage.out; \
			rm -f $(COVERAGE_DIR)/pkg.out; \
		fi; \
	done
	@go tool cover -func=$(COVERAGE_DIR)/coverage.out
	@echo ""
	@echo "HTML report: $(COVERAGE_DIR)/coverage.html"
	@go tool cover -html=$(COVERAGE_DIR)/coverage.out -o $(COVERAGE_DIR)/coverage.html
	@echo ""
	@TOTAL=$$(go tool cover -func=$(COVERAGE_DIR)/coverage.out | grep '^total:' | awk '{print $$NF}'); \
	echo "=== TOTAL CODE COVERAGE: $$TOTAL ==="; \
	PCT=$$(echo "$$TOTAL" | tr -d '%'); \
	if [ $$(echo "$$PCT < $(COVERAGE_MIN)" | bc -l 2>/dev/null || echo 0) -eq 1 ]; then \
		echo "FAIL: Coverage $$TOTAL is below minimum $(COVERAGE_MIN)%"; \
		exit 1; \
	else \
		echo "PASS: Coverage $$TOTAL meets minimum $(COVERAGE_MIN)%"; \
	fi

# Package-specific coverage targets: make coverage-cipher, make coverage-poksho, etc.
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
	TOTAL=$$(go tool cover -func=$(COVERAGE_DIR)/$(subst /,_,$(subst coverage-,,$@)).out | grep '^total:' | awk '{print $$NF}'); \
	echo "=== $(subst coverage-,,$@) COVERAGE: $$TOTAL (min: $$PKG_MIN%) ==="; \
	PCT=$$(echo "$$TOTAL" | tr -d '%'); \
	if [ $$(echo "$$PCT < $$PKG_MIN" | bc -l 2>/dev/null || echo 0) -eq 1 ]; then \
		echo "FAIL: Coverage $$TOTAL is below minimum $$PKG_MIN%"; \
		exit 1; \
	else \
		echo "PASS: Coverage $$TOTAL meets minimum $$PKG_MIN%"; \
	fi

# Internal helper targets for per-package minimum lookup.
_pkg_min_pkg_groups_ratchet:
	@echo $(COVERAGE_MIN_groups_ratchet)
_pkg_min_pkg_mlkembraid:
	@echo $(COVERAGE_MIN_mlkembraid)
_pkg_min_pkg_tripleratchet:
	@echo $(COVERAGE_MIN_tripleratchet)
_pkg_min_pkg_util_crypto_secret:
	@echo $(COVERAGE_MIN_util_crypto_secret)

# ==============================================================================
# Benchmarks
# ==============================================================================

bench:
	$(GOTEST) -bench=. -benchmem ./...

# Package-specific benchmark targets: make bench-cipher, make bench-poksho, etc.
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

lint:
	@which golangci-lint > /dev/null 2>&1 || \
		(echo "Installing golangci-lint..." && \
		go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest)
	golangci-lint run ./...

# ==============================================================================
# Security Scanning
# ==============================================================================

gosec:
	@which gosec > /dev/null 2>&1 || \
		(echo "Installing gosec..." && \
		go install github.com/securego/gosec/v2/cmd/gosec@latest)
	gosec -fmt=text -severity=medium -exclude=G115 ./...

govulncheck:
	@which govulncheck > /dev/null 2>&1 || \
		(echo "Installing govulncheck..." && \
		go install golang.org/x/vuln/cmd/govulncheck@latest)
	govulncheck ./...

staticcheck:
	@which staticcheck > /dev/null 2>&1 || \
		(echo "Installing staticcheck..." && \
		go install honnef.co/go/tools/cmd/staticcheck@latest)
	staticcheck ./...

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

ci: fmtcheck vet lint security test coverage examples-build

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
	@echo "    make test-PACKAGE       - Run tests for a specific package"
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
	@echo "    make coverage-PACKAGE   - Generate coverage for a specific package"
	@echo ""
	@echo "  Benchmarks:"
	@echo "    make bench              - Run all benchmarks"
	@echo "    make bench-PACKAGE      - Run benchmarks for a specific package"
	@echo ""
	@echo "  Quality:"
	@echo "    make vet                - Run go vet"
	@echo "    make lint               - Run golangci-lint"
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
