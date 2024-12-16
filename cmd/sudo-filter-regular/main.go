// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package main

import (
	"io"
	"log"
	"os"

	"github.com/theparanoids/pam-ysshca/filter"
)

func main() {
	f := &filter.SudoFilterRegular{}
	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("failed to read from stdin, %v", err)
	}
	out := f.Filter(in)
	os.Stdout.Write(out)
}
