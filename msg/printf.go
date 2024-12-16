// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package msg

import (
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	prefixDebug = "[DEBUG] "
	prefixInfo  = "[INFO] "
	prefixWarn  = "[WARN] "
	prefixError = "[ERROR] "
	prefixFatal = "[FATAL] "
)

// Level defines the log level of the message that is printed to the user.
// Debug level messages are printed to the user only when debug mode is on.
type Level uint

const (
	DEBUG Level = iota
	INFO
	WARN
	ERROR
	FATAL
)

var (
	m = new(os.Stderr, false)
)

type msg struct {
	debugMode bool
	out       io.Writer
}

func new(out io.Writer, debugMode bool) *msg {
	return &msg{
		debugMode: debugMode,
		out:       out,
	}
}

// Printf prints formatted strings on the terminals to user.
func Printf(str string, objs ...interface{}) {
	m.printf(str, objs...)
}

func (m *msg) printf(str string, objs ...interface{}) {
	output := fmt.Sprintf(str, objs...)
	fmt.Fprintf(m.out, "%v", output)
}

// Print prints the given string on the terminals to user.
func Print(str string) {
	m.print(str)
}

func (m *msg) print(str string) {
	fmt.Fprint(m.out, str)
}

// Printlf prints formatted strings with a message level prefix on the terminals to user.
func Printlf(level Level, str string, objs ...interface{}) {
	m.printlf(level, str, objs...)
}

func (m *msg) printlf(level Level, str string, objs ...interface{}) {
	if level == DEBUG && !m.debugMode {
		return
	}
	switch level {
	case DEBUG:
		str = prefixDebug + str
	case INFO:
		str = prefixInfo + str
	case WARN:
		str = prefixWarn + str
	case ERROR:
		str = prefixError + str
	case FATAL:
		str = prefixFatal + str
	}
	output := strings.TrimSpace(fmt.Sprintf(str, objs...))
	fmt.Fprintf(m.out, "%v\n", output)
}

// SetDebugMode set the debug mode.
// Debug level message sent to user only when debug mode is on.
func SetDebugMode(debugMode bool) {
	m.debugMode = debugMode
}

// SetWriter sets the io writer to the msg.
func SetWriter(writer io.Writer) {
	m.out = writer
}
