// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package decoder

import "fmt"

// token is a carrier being passed from lexer to parser, which representing a field in the config.
type token struct {
	Position
	typ tokenType
	val string
}

// String returns the string of a token.
func (t token) String() string {
	switch t.typ {
	case tokenEOF:
		return "EOF"
	}
	return fmt.Sprintf("%q", t.val)
}

type tokenType int

const (
	eof = -(iota + 1)
)

const (
	tokenError tokenType = iota
	tokenEOF
	tokenEmptyLine
	tokenComment
	tokenKey
	tokenString
)

func isSpace(r rune) bool {
	return r == ' ' || r == '\t'
}

func isStartOfKey(r rune) bool {
	return !(isSpace(r) || r == '\r' || r == '\n' || r == eof)
}

// isValidKeyChar checks whether r is a valid rune in a key.
// Keys shouldn't contain following characters.
// For example, the existence of '=' or '\n' means the end of the key.
func isValidKeyChar(r rune) bool {
	return !(r == '\r' || r == '\n' || r == eof || r == '=')
}
