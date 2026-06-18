// Package live provides a Go client harness for the interop_runner Rust binary.
//
// The harness spawns interop_runner once per test binary invocation, pipes
// newline-delimited JSON commands to its stdin, and reads JSON responses from
// stdout. A single process is cached across all tests via sync.Once; the
// cleanup function registered with testing.M (or the first test's t.Cleanup)
// shuts it down gracefully.
//
//go:build interop_live

package live

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
)

// ErrRunnerNotFound is returned when the interop_runner binary cannot be located.
type ErrRunnerNotFound struct {
	Path string
}

func (e *ErrRunnerNotFound) Error() string {
	return fmt.Sprintf("interop_runner binary not found at %q; run 'make interop-live-build' first", e.Path)
}

// ErrRunnerCommand is returned when the runner responds with an "error" field.
type ErrRunnerCommand struct {
	Op  string
	Msg string
}

func (e *ErrRunnerCommand) Error() string {
	return fmt.Sprintf("interop_runner op %q error: %s", e.Op, e.Msg)
}

// runnerBinPath returns the path to the interop_runner binary.
// It checks LIBSIGNAL_INTEROP_LIVE_BIN first, then falls back to the
// default release path relative to this source file.
func runnerBinPath() string {
	if v := os.Getenv("LIBSIGNAL_INTEROP_LIVE_BIN"); v != "" {
		return v
	}
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "rust", "target", "release", "interop_runner")
}

// Runner manages a single long-lived interop_runner process.
type Runner struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Scanner
}

var (
	globalRunner     *Runner
	globalRunnerOnce sync.Once
	globalRunnerErr  error
)

// GlobalRunner returns the singleton Runner, starting it on first call.
// The caller should register a cleanup via t.Cleanup(GlobalRunner.Stop) if
// needed, but since the process is shared the Makefile target is expected
// to be short-lived.
func GlobalRunner() (*Runner, error) {
	globalRunnerOnce.Do(func() {
		r, err := newRunner(runnerBinPath())
		if err != nil {
			globalRunnerErr = err
			return
		}
		globalRunner = r
	})
	return globalRunner, globalRunnerErr
}

// newRunner starts the interop_runner binary and returns a Runner.
func newRunner(binPath string) (*Runner, error) {
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		return nil, &ErrRunnerNotFound{Path: binPath}
	}

	cmd := exec.Command(binPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("interop_runner stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("interop_runner stdout pipe: %w", err)
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting interop_runner: %w", err)
	}

	return &Runner{
		cmd:    cmd,
		stdin:  stdin,
		stdout: bufio.NewScanner(stdout),
	}, nil
}

// Stop shuts down the runner gracefully.
func (r *Runner) Stop() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_ = r.stdin.Close()
	_ = r.cmd.Wait()
}

// RunCommand sends a command to the runner and returns the parsed response.
// The command map must include an "op" key. The runner appends "seed_hex" if
// not already present. Thread-safe: commands are serialized via the mutex.
func (r *Runner) RunCommand(cmd map[string]any) (map[string]json.RawMessage, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	data, err := json.Marshal(cmd)
	if err != nil {
		return nil, fmt.Errorf("marshal command: %w", err)
	}

	if _, err := fmt.Fprintf(r.stdin, "%s\n", data); err != nil {
		return nil, fmt.Errorf("writing command to runner: %w", err)
	}

	if !r.stdout.Scan() {
		if err := r.stdout.Err(); err != nil {
			return nil, fmt.Errorf("reading runner response: %w", err)
		}
		return nil, fmt.Errorf("runner closed stdout unexpectedly")
	}

	line := r.stdout.Bytes()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(line, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal runner response %q: %w", string(line), err)
	}

	// Check for error field.
	if errRaw, hasErr := raw["error"]; hasErr {
		var errMsg string
		if err := json.Unmarshal(errRaw, &errMsg); err == nil && errMsg != "" {
			op, _ := cmd["op"].(string)
			return nil, &ErrRunnerCommand{Op: op, Msg: errMsg}
		}
	}

	return raw, nil
}

// GetString extracts a string field from a runner response.
func GetString(resp map[string]json.RawMessage, key string) (string, error) {
	raw, ok := resp[key]
	if !ok {
		return "", fmt.Errorf("runner response missing field %q", key)
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", fmt.Errorf("field %q: %w", key, err)
	}
	return v, nil
}
