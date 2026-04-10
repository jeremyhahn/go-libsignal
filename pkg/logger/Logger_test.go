package logger

import (
	"strings"
	"sync"
	"testing"
)

// testLogger captures log calls for testing
type testLogger struct {
	debugCalls   []string
	infoCalls    []string
	warningCalls []string
	errorCalls   []string
	configCalls  []string
}

func (t *testLogger) Debug(caller, message string) {
	t.debugCalls = append(t.debugCalls, caller+": "+message)
}

func (t *testLogger) Info(caller, message string) {
	t.infoCalls = append(t.infoCalls, caller+": "+message)
}

func (t *testLogger) Warning(caller, message string) {
	t.warningCalls = append(t.warningCalls, caller+": "+message)
}

func (t *testLogger) Error(caller, message string) {
	t.errorCalls = append(t.errorCalls, caller+": "+message)
}

func (t *testLogger) Configure(settings string) {
	t.configCalls = append(t.configCalls, settings)
}

func setupTestLogger() *testLogger {
	tl := &testLogger{}
	var loggable Loggable = tl
	Setup(&loggable)
	return tl
}

func TestSetup(t *testing.T) {
	setupTestLogger()
	if Get() == nil {
		t.Fatal("Logger should not be nil after Setup")
	}
}

func TestDebug(t *testing.T) {
	tl := setupTestLogger()
	Debug("hello", " world")
	if len(tl.debugCalls) != 1 {
		t.Fatalf("expected 1 debug call, got %d", len(tl.debugCalls))
	}
	if !strings.Contains(tl.debugCalls[0], "hello world") {
		t.Fatalf("expected debug message containing 'hello world', got %q", tl.debugCalls[0])
	}
}

func TestInfo(t *testing.T) {
	tl := setupTestLogger()
	Info("info message")
	if len(tl.infoCalls) != 1 {
		t.Fatalf("expected 1 info call, got %d", len(tl.infoCalls))
	}
	if !strings.Contains(tl.infoCalls[0], "info message") {
		t.Fatalf("expected 'info message', got %q", tl.infoCalls[0])
	}
}

func TestWarning(t *testing.T) {
	tl := setupTestLogger()
	Warning("warn message")
	if len(tl.warningCalls) != 1 {
		t.Fatalf("expected 1 warning call, got %d", len(tl.warningCalls))
	}
}

func TestError(t *testing.T) {
	tl := setupTestLogger()
	Error("error message")
	if len(tl.errorCalls) != 1 {
		t.Fatalf("expected 1 error call, got %d", len(tl.errorCalls))
	}
}

func TestConfigure(t *testing.T) {
	tl := setupTestLogger()
	Configure("Curve.go,RootKey.go")
	if len(tl.configCalls) != 1 {
		t.Fatalf("expected 1 configure call, got %d", len(tl.configCalls))
	}
	if tl.configCalls[0] != "Curve.go,RootKey.go" {
		t.Fatalf("expected 'Curve.go,RootKey.go', got %q", tl.configCalls[0])
	}
}

func TestEnsureLogger_DefaultLogger(t *testing.T) {
	// Clear the atomic logger so ensureLogger installs the default.
	atomicLogger.Store(&loggerHolder{l: nil})
	// Reset the once so the default can be re-installed.
	defaultOnce = sync.Once{}
	ensureLogger()
	if Get() == nil {
		t.Fatal("ensureLogger should set logger to default when nil")
	}
}

func TestEnsureLogger_KeepsExisting(t *testing.T) {
	tl := setupTestLogger()
	ensureLogger()
	// Logger should still be our test logger.
	Debug("test")
	if len(tl.debugCalls) != 1 {
		t.Fatal("ensureLogger should not replace existing logger")
	}
}

func TestGetCaller(t *testing.T) {
	caller := getCaller()
	if caller == "" {
		t.Fatal("getCaller should not return empty string")
	}
	// Should contain filename and line number
	if !strings.Contains(caller, ".go:") {
		t.Fatalf("getCaller should return file:line format, got %q", caller)
	}
}

func TestToString(t *testing.T) {
	result := toString("hello", " ", "world")
	if result != "hello world" {
		t.Fatalf("expected 'hello world', got %q", result)
	}
}

func TestToString_MixedTypes(t *testing.T) {
	result := toString("count: ", 42)
	if result != "count: 42" {
		t.Fatalf("expected 'count: 42', got %q", result)
	}
}

func TestDebug_MultipleArgs(t *testing.T) {
	tl := setupTestLogger()
	Debug("value is ", 42, " and ", true)
	if len(tl.debugCalls) != 1 {
		t.Fatal("expected 1 debug call")
	}
	if !strings.Contains(tl.debugCalls[0], "42") {
		t.Fatalf("expected message to contain '42', got %q", tl.debugCalls[0])
	}
}

// Test the default logger directly
func TestDefaultLogger_Debug(t *testing.T) {
	dl := &defaultLogger{}
	// Should not panic
	dl.Debug("test.go:1", "debug message")
}

func TestDefaultLogger_Info(t *testing.T) {
	dl := &defaultLogger{}
	dl.Info("test.go:1", "info message")
}

func TestDefaultLogger_Warning(t *testing.T) {
	dl := &defaultLogger{}
	dl.Warning("test.go:1", "warning message")
}

func TestDefaultLogger_Error(t *testing.T) {
	dl := &defaultLogger{}
	dl.Error("test.go:1", "error message")
}

func TestDefaultLogger_Configure(t *testing.T) {
	dl := &defaultLogger{}
	dl.Configure("Curve.go,RootKey.go")
	if len(dl.namespaces) != 2 {
		t.Fatalf("expected 2 namespaces, got %d", len(dl.namespaces))
	}
	if dl.namespaces[0] != "Curve.go" || dl.namespaces[1] != "RootKey.go" {
		t.Fatal("namespace mismatch")
	}
}

func TestDefaultLogger_ShouldLog_AllNamespace(t *testing.T) {
	dl := &defaultLogger{}
	// Default namespaces should include "all"
	if !dl.shouldLog("anything.go:1") {
		t.Fatal("should log with 'all' namespace")
	}
}

func TestDefaultLogger_ShouldLog_SpecificNamespace(t *testing.T) {
	dl := &defaultLogger{}
	dl.Configure("Curve.go")
	if !dl.shouldLog("Curve.go:42") {
		t.Fatal("should log when caller matches namespace")
	}
	if dl.shouldLog("RootKey.go:1") {
		t.Fatal("should not log when caller does not match namespace")
	}
}

func TestDefaultLogger_EnsureNamespaces(t *testing.T) {
	dl := &defaultLogger{}
	dl.ensureNamespaces()
	if len(dl.namespaces) != 1 || dl.namespaces[0] != "all" {
		t.Fatal("ensureNamespaces should default to 'all'")
	}
}

func TestDefaultLogger_EnsureNamespaces_AlreadySet(t *testing.T) {
	dl := &defaultLogger{namespaces: []string{"Curve.go"}}
	dl.ensureNamespaces()
	if len(dl.namespaces) != 1 || dl.namespaces[0] != "Curve.go" {
		t.Fatal("ensureNamespaces should not overwrite existing namespaces")
	}
}

func TestDefaultLogger_Log_FilteredOut(t *testing.T) {
	dl := &defaultLogger{}
	dl.Configure("OnlyThisFile.go")
	// This should not panic; the message is simply filtered
	dl.log("DEBUG", "OtherFile.go:1", "should be filtered")
}

// safeTestLogger is a goroutine-safe logger used in the concurrency test.
type safeTestLogger struct {
	mu    sync.Mutex
	calls int
}

func (s *safeTestLogger) Debug(caller, message string)   { s.mu.Lock(); s.calls++; s.mu.Unlock() }
func (s *safeTestLogger) Info(caller, message string)    { s.mu.Lock(); s.calls++; s.mu.Unlock() }
func (s *safeTestLogger) Warning(caller, message string) { s.mu.Lock(); s.calls++; s.mu.Unlock() }
func (s *safeTestLogger) Error(caller, message string)   { s.mu.Lock(); s.calls++; s.mu.Unlock() }
func (s *safeTestLogger) Configure(settings string)      {}

// TestSetup_Concurrent verifies that concurrent Setup and logging calls are race-free.
// Each goroutine installs a shared goroutine-safe logger; the atomic.Value store
// and load must not race.
func TestSetup_Concurrent(t *testing.T) {
	sl := &safeTestLogger{}
	var l Loggable = sl
	Setup(&l)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			Debug("concurrent test")
		}()
	}
	wg.Wait()
}

// TestGet_NilBeforeSetup verifies that Get returns nil when the loggerHolder
// explicitly stores a nil Loggable.
func TestGet_NilLoggerHolder(t *testing.T) {
	atomicLogger.Store(&loggerHolder{l: nil})
	defaultOnce = sync.Once{}
	if Get() != nil {
		t.Fatal("Get should return nil when holder contains nil Loggable")
	}
}
