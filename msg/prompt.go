// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package msg

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

const prefix = ">>>"

// Prompter contains the logic to interact with users.
type Prompter struct {
	reader *bufio.Reader
}

// NewPrompter returns a new Prompter.
func NewPrompter() *Prompter {
	reader := bufio.NewReader(os.Stdin)
	return &Prompter{
		reader: reader,
	}
}

// Prompt prompts message to users.
func (p *Prompter) Prompt(m string) {
	Printf("\n%s %s\n", prefix, m)
}

// Promptf prompts message to users.
func (p *Prompter) Promptf(str string, objs ...interface{}) {
	p.Prompt(fmt.Sprintf(str, objs...))
}

// ReadString reads input string from users.
func (p *Prompter) ReadString() (string, error) {
	str, err := p.reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read input data, err: %v", err)
	}
	return strings.TrimSpace(str), nil
}
