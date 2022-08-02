// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package msg

import (
	"os"
)

func Example_printf() {
	SetWriter(os.Stdout)
	defer SetWriter(os.Stderr)
	Printf("hello")
	// Output:
	// hello
}

func Example_printlf() {
	SetWriter(os.Stdout)
	defer SetWriter(os.Stderr)
	Printlf(DEBUG, "debug mode is off")
	SetDebugMode(true)
	Printlf(DEBUG, "debug mode is on")
	// Output:
	// [DEBUG] debug mode is on
}
