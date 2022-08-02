// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package decoder

import (
	"fmt"
	"strings"
)

// Node represents a line or an entry in the pam Config.
type Node interface {
	Pos() Position
	String() string
}

// KV is a line in the config file that contains a key, a value, and possibly
// a comment.
type KV struct {
	Key      string
	Value    string
	Comment  string
	position Position
}

// Pos returns k's Position.
func (k *KV) Pos() Position {
	return k.position
}

// String returns the string of KV.
func (k *KV) String() string {
	if k == nil {
		return ""
	}
	equals := " "
	line := fmt.Sprintf("%s%s%s", k.Key, equals, k.Value)
	line = strings.TrimSpace(line)
	if k.Comment != "" {
		line += " #" + k.Comment
	}
	return line
}

// Empty is a line in the config file that contains only whitespace or comments.
type Empty struct {
	Comment      string
	leadingSpace int
	position     Position
}

// Pos returns e's Position.
func (e *Empty) Pos() Position {
	return e.position
}

// String returns the string of Empty.
func (e *Empty) String() string {
	if e == nil {
		return ""
	}
	if e.Comment == "" {
		return ""
	}
	return fmt.Sprintf("%s#%s", strings.Repeat(" ", e.leadingSpace), e.Comment)
}
