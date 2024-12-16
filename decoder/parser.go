// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package decoder

import (
	"fmt"
)

// parser consumes the tokens fed from lexer and composes Config with Nodes.
type parser struct {
	flow         chan token
	config       *Config
	tokensBuffer []token
}

type StateFn func() StateFn

func (p *parser) raiseErrorf(tok *token, msg string, args ...interface{}) {
	panic(tok.Position.String() + ": " + fmt.Sprintf(msg, args...))
}

func (p *parser) run() {
	for state := p.parseStart; state != nil; {
		state = state()
	}
}

func (p *parser) peek() *token {
	if len(p.tokensBuffer) != 0 {
		return &(p.tokensBuffer[0])
	}

	tok, ok := <-p.flow
	if !ok {
		return nil
	}
	p.tokensBuffer = append(p.tokensBuffer, tok)
	return &tok
}

func (p *parser) getToken() *token {
	if len(p.tokensBuffer) != 0 {
		tok := p.tokensBuffer[0]
		p.tokensBuffer = p.tokensBuffer[1:]
		return &tok
	}
	tok, ok := <-p.flow
	if !ok {
		return nil
	}
	return &tok
}

func (p *parser) parseStart() StateFn {
	tok := p.peek()

	// end of stream, parsing is finished
	if tok == nil {
		return nil
	}

	switch tok.typ {
	case tokenComment, tokenEmptyLine:
		return p.parseComment
	case tokenKey:
		return p.parseKV
	case tokenEOF:
		return nil
	default:
		p.raiseErrorf(tok, "unexpected token %q\n", tok)
	}
	return nil
}

func (p *parser) parseKV() StateFn {
	key := p.getToken()
	val := p.getToken()
	comment := ""
	tok := p.peek()
	if tok == nil {
		tok = &token{typ: tokenEOF}
	}
	if tok.typ == tokenComment && tok.Position.Line == val.Position.Line {
		tok = p.getToken()
		comment = tok.val
	}
	kv := &KV{
		Key:      key.val,
		Value:    val.val,
		Comment:  comment,
		position: key.Position,
	}
	p.config.Nodes = append(p.config.Nodes, kv)
	return p.parseStart
}

func (p *parser) parseComment() StateFn {
	comment := p.getToken()
	p.config.Nodes = append(p.config.Nodes, &Empty{
		Comment: comment.val,
		// account for the "#" as well
		leadingSpace: comment.Position.Col - 2,
		position:     comment.Position,
	})
	return p.parseStart
}

func parse(flow chan token) *Config {
	// Ensure we consume tokens to completion even if parser exits early
	defer func() {
		for range flow {
		}
	}()

	result := newConfig()
	parser := &parser{
		flow:         flow,
		config:       result,
		tokensBuffer: make([]token, 0),
	}
	parser.run()
	return result
}
