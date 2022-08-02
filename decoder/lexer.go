// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package decoder

import (
	"bytes"
)

// lexStateFn is the state function that transit among token types.
type lexStateFn func() lexStateFn

type lexer struct {
	inputIdx int
	// input is the textual source from pam config.
	input []rune
	// buffer is the current token that is read from the entry.
	buffer []rune
	// tokens is the channel that lexer sends the current token (key or value) to parser.
	tokens        chan token
	line          int
	col           int
	endBufferLine int
	endBufferCol  int
}

// lexVoid is the initial stage of each line in the pam config.
func (s *lexer) lexVoid() lexStateFn {
	for {
		next := s.peek()
		switch next {
		case '#':
			s.skip()
			return s.lexComment(s.lexVoid)
		case '\r':
			fallthrough
		case '\n':
			s.emit(tokenEmptyLine)
			s.skip()
			continue
		}

		if isSpace(next) {
			s.skip()
		}

		if isStartOfKey(next) {
			return s.lexKey
		}

		if next == eof {
			s.next()
			break
		}
	}

	s.emit(tokenEOF)
	return nil
}

func (s *lexer) lexComment(previousState lexStateFn) lexStateFn {
	return func() lexStateFn {
		growingString := ""
		for next := s.peek(); next != '\n' && next != eof; next = s.peek() {
			if next == '\r' && s.follow("\r\n") {
				break
			}
			growingString += string(next)
			s.next()
		}
		s.emitWithValue(tokenComment, growingString)
		s.skip()
		return previousState
	}
}

func (s *lexer) lexKey() lexStateFn {
	growingString := ""

	for r := s.peek(); isValidKeyChar(r); r = s.peek() {
		if isSpace(r) {
			s.emitWithValue(tokenKey, growingString)
			s.skip()
			return s.lexRSpace()
		}
		growingString += string(r)
		s.next()
	}
	s.emitWithValue(tokenKey, growingString)
	return s.lexRvalue()
}

// lexRSpace lex all the spaces after a space followed by a key.
func (s *lexer) lexRSpace() lexStateFn {
	for {
		next := s.peek()
		if !isSpace(next) {
			break
		}
		s.skip()
	}
	return s.lexRvalue
}

// lexRvalue lex the value until the end of a line.
func (s *lexer) lexRvalue() lexStateFn {
	growingString := ""
	for {
		next := s.peek()
		switch next {
		case '\r':
			if s.follow("\r\n") {
				s.emitWithValue(tokenString, growingString)
				s.skip()
				return s.lexVoid
			}
		case '\n':
			s.emitWithValue(tokenString, growingString)
			s.skip()
			return s.lexVoid
		case '#':
			s.emitWithValue(tokenString, growingString)
			s.skip()
			return s.lexComment(s.lexVoid)
		case eof:
			s.next()
		}
		if next == eof {
			break
		}
		growingString += string(next)
		s.next()
	}
	s.emit(tokenEOF)
	return nil
}

func (s *lexer) read() rune {
	r := s.peek()
	if r == '\n' {
		s.endBufferLine++
		s.endBufferCol = 1
	} else {
		s.endBufferCol++
	}
	s.inputIdx++
	return r
}

func (s *lexer) next() rune {
	r := s.read()
	if r != eof {
		s.buffer = append(s.buffer, r)
	}
	return r
}

func (s *lexer) ignore() {
	s.buffer = make([]rune, 0)
	s.line = s.endBufferLine
	s.col = s.endBufferCol
}

func (s *lexer) skip() {
	s.next()
	s.ignore()
}

func (s *lexer) emit(t tokenType) {
	s.emitWithValue(t, string(s.buffer))
}

func (s *lexer) emitWithValue(t tokenType, value string) {
	tok := token{
		Position: Position{s.line, s.col},
		typ:      t,
		val:      value,
	}
	s.tokens <- tok
	s.ignore()
}

func (s *lexer) peek() rune {
	if s.inputIdx >= len(s.input) {
		return eof
	}

	r := s.input[s.inputIdx]
	return r
}

func (s *lexer) follow(next string) bool {
	inputIdx := s.inputIdx
	for _, expectedRune := range next {
		if inputIdx >= len(s.input) {
			return false
		}
		r := s.input[inputIdx]
		inputIdx++
		if expectedRune != r {
			return false
		}
	}
	return true
}

func (s *lexer) run() {
	for state := s.lexVoid; state != nil; {
		state = state()
	}
	close(s.tokens)
}

func lexPAM(input []byte) chan token {
	runes := bytes.Runes(input)
	l := &lexer{
		input:         runes,
		tokens:        make(chan token),
		line:          1,
		col:           1,
		endBufferLine: 1,
		endBufferCol:  1,
	}
	go l.run()
	return l.tokens
}
