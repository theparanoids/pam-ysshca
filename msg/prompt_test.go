// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package msg

import (
	"os"
)

func ExamplePrompter_Prompt() {
	// Disable parallel because we temporarily redirect the writer.
	SetWriter(os.Stdout)
	defer SetWriter(os.Stderr)
	p := NewPrompter()
	p.Prompt("hello")
	// Output:
	// >>> hello
}

func ExamplePrompter_Promptf() {
	// Disable parallel because we temporarily redirect the writer.
	SetWriter(os.Stdout)
	defer SetWriter(os.Stderr)
	p := NewPrompter()
	p.Promptf("%s\n %s", "some", "message")
	// Output:
	// >>> some
	//  message
}
