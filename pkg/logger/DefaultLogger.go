package logger

import (
	"fmt"
	"strings"
	"time"
)

// DefaultLogger is used if no logger has been set up.
type defaultLogger struct {
	namespaces []string
}

// log simply logs the given message to stdout if the message
// caller is allowed to log.
func (d *defaultLogger) log(level, caller, msg string) {
	if !d.shouldLog(caller) {
		return
	}
	t := time.Now()
	fmt.Println(
		"["+level+"]",
		t.Format(time.RFC3339),
		caller,
		"▶ ",
		msg,
	)
}

// shouldLog determines whether or not the given caller should
// be allowed to log messages.
func (d *defaultLogger) shouldLog(caller string) bool {
	shouldLog := false
	d.ensureNamespaces()
	for _, namespace := range d.namespaces {
		if namespace == "all" {
			shouldLog = true
		}
		if strings.Contains(caller, namespace) {
			shouldLog = true
		}
	}

	return shouldLog
}

// ensureNamespaces checks to see if our list of loggable namespaces
// has been initialized or not. If not, it defaults to log all.
func (d *defaultLogger) ensureNamespaces() {
	if d.namespaces == nil {
		d.namespaces = []string{"all"}
	}
}

// Debug is used to log debug messages.
func (d *defaultLogger) Debug(caller, msg string) {
	d.log("DEBUG", caller, msg)
}

// Info is used to log info messages.
func (d *defaultLogger) Info(caller, msg string) {
	d.log("INFO", caller, msg)
}

// Warning is used to log warning messages.
func (d *defaultLogger) Warning(caller, msg string) {
	d.log("WARNING", caller, msg)
}

// Error is used to log error messages.
func (d *defaultLogger) Error(caller, msg string) {
	d.log("ERROR", caller, msg)
}

// Configure sets the comma-separated caller files to log, or "all", e.g. logger.Configure("RootKey.go,Curve.go").
func (d *defaultLogger) Configure(settings string) {
	d.namespaces = strings.Split(settings, ",")
}
