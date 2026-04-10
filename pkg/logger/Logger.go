// Package logger provides optional debug logging of the Signal library.
package logger

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// loggerValue holds the atomic storage for the active Loggable.
// atomic.Value requires the same concrete type on every Store call, so we
// store a *loggerHolder rather than a bare interface.
type loggerHolder struct {
	l Loggable
}

var (
	atomicLogger atomic.Value // stores *loggerHolder
	defaultOnce  sync.Once
)

// Loggable is an interface for logging.
type Loggable interface {
	Debug(caller, message string)
	Info(caller, message string)
	Warning(caller, message string)
	Error(caller, message string)
	Configure(settings string)
}

// Setup configures the shared logger to use the provided logger.
// It is safe to call from multiple goroutines.
func Setup(logger *Loggable) {
	atomicLogger.Store(&loggerHolder{l: *logger})
}

// Get returns the current Loggable, or nil if none has been set.
// It is safe to call from multiple goroutines.
func Get() Loggable {
	v := atomicLogger.Load()
	if v == nil {
		return nil
	}
	return v.(*loggerHolder).l
}

// toString converts an arbitrary number of objects to a string for use in a logger.
func toString(a ...interface{}) string {
	return fmt.Sprint(a...)
}

// ensureLogger initialises the default logger exactly once when no custom
// logger has been configured.  It is safe to call from multiple goroutines.
func ensureLogger() {
	if Get() != nil {
		return
	}
	defaultOnce.Do(func() {
		// Only install the default if still unset (Setup may have raced).
		if Get() == nil {
			fmt.Println("Error: No logger was configured. Use `logger.Setup` to configure a logger.")
			dl := &defaultLogger{}
			var l Loggable = dl
			atomicLogger.Store(&loggerHolder{l: l})
		}
	})
}

// getCaller returns the go file name and line number the logger was called from.
func getCaller() string {
	var file string
	_, path, line, _ := runtime.Caller(2)
	paths := strings.Split(path, "/")
	if len(paths) > 0 {
		file = paths[len(paths)-1]
	} else {
		file = "<unkn>"
	}
	return file + ":" + strconv.Itoa(line)
}

/*
 * Package-level logging functions used by the library.
 */

// Debug prints debug level logs.
func Debug(msg ...interface{}) {
	ensureLogger()
	Get().Debug(getCaller(), toString(msg...))
}

// Info prints info level logs.
func Info(msg ...interface{}) {
	ensureLogger()
	Get().Info(getCaller(), toString(msg...))
}

// Warning prints warning level logs.
func Warning(msg ...interface{}) {
	ensureLogger()
	Get().Warning(getCaller(), toString(msg...))
}

// Error prints error level logs.
func Error(msg ...interface{}) {
	ensureLogger()
	Get().Error(getCaller(), toString(msg...))
}

// Configure allows arbitrary logger configuration settings.
func Configure(settings string) {
	ensureLogger()
	Get().Configure(settings)
}
