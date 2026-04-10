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
GOBIN := $(shell go env GOPATH)/bin
export PATH := $(GOBIN):$(PATH)

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
	pkg/tripleratchet pkg/usernames pkg/util/bytehelper pkg/util/crypto pkg/util/crypto/secret \
	pkg/util/errorhelper pkg/util/keyhelper pkg/util/optional pkg/crypto/elligator pkg/crypto/keyops \
	pkg/zkcredential pkg/zkgroup

.PHONY: all build test test-verbose integration-test vet lint clean coverage help \
	ci security gosec govulncheck staticcheck errcheck nilcheck

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
$(addprefix coverage-,$(TESTABLE_PACKAGES)):
	@mkdir -p $(COVERAGE_DIR)
	@$(GOTEST) -coverprofile=$(COVERAGE_DIR)/$(subst /,_,$(subst coverage-,,$@)).out \
		-covermode=atomic ./$(subst coverage-,,$@)/...
	@go tool cover -func=$(COVERAGE_DIR)/$(subst /,_,$(subst coverage-,,$@)).out
	@echo ""
	@TOTAL=$$(go tool cover -func=$(COVERAGE_DIR)/$(subst /,_,$(subst coverage-,,$@)).out | grep '^total:' | awk '{print $$NF}'); \
	echo "=== $(subst coverage-,,$@) COVERAGE: $$TOTAL ==="; \
	PCT=$$(echo "$$TOTAL" | tr -d '%'); \
	if [ $$(echo "$$PCT < $(COVERAGE_MIN)" | bc -l 2>/dev/null || echo 0) -eq 1 ]; then \
		echo "FAIL: Coverage $$TOTAL is below minimum $(COVERAGE_MIN)%"; \
		exit 1; \
	else \
		echo "PASS: Coverage $$TOTAL meets minimum $(COVERAGE_MIN)%"; \
	fi

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

lint:
	@which golangci-lint > /dev/null 2>&1 || \
		(echo "Installing golangci-lint..." && \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
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

security: gosec govulncheck staticcheck

# ==============================================================================
# CI
# ==============================================================================

ci: vet lint security test coverage

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
	@echo "    make security           - Run all security scanners (gosec, govulncheck, staticcheck)"
	@echo "    make gosec              - Run gosec (common Go security issues)"
	@echo "    make govulncheck        - Run govulncheck (known dependency vulnerabilities)"
	@echo "    make staticcheck        - Run staticcheck (advanced static analysis)"
	@echo "    make errcheck           - Run errcheck (unchecked error returns)"
	@echo "    make nilcheck           - Run nilaway (nil dereference analysis, non-blocking)"
	@echo ""
	@echo "  CI:"
	@echo "    make ci                 - Run full CI pipeline: vet lint security test coverage"
	@echo ""
	@echo "  Maintenance:"
	@echo "    make clean              - Clean coverage files and test cache"
	@echo "    make help               - Show this help"
