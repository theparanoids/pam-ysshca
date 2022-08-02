// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package decoder

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"strings"
)

// Config represents a decoded PAM config file.
type Config struct {
	// A Node is either a key/value pair or a comment line.
	Nodes []Node
}

func newConfig() *Config {
	return &Config{
		Nodes: make([]Node, 0),
	}
}

// Decode decodes the bytes read from config file.
func Decode(b []byte) (c *Config, err error) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(runtime.Error); ok {
				panic(r)
			}
			err = errors.New(r.(string))
		}
	}()

	c = parse(lexPAM(b))
	return c, err
}

// Get finds the first value in the configuration entry that matches the key.
// It returns the empty string if no value was found.
func (c *Config) Get(key string) (string, error) {
	node, err := c.GetKV(key)
	if err != nil {
		return "", err
	}
	if node == nil {
		return "", nil
	}
	return strings.TrimSpace(node.Value), nil
}

// GetAll returns all values in the configuration that match the key, or nil if none are present.
func (c *Config) GetAll(key string) ([]string, error) {
	nodes, err := c.GetAllKVs(key)
	if err != nil {
		return nil, err
	}
	var all []string
	for _, node := range nodes {
		all = append(all, strings.TrimSpace(node.Value))
	}
	return all, nil
}

// GetKV returns the KV node that match the key.
func (c *Config) GetKV(key string) (*KV, error) {
	lowerKey := strings.ToLower(key)
	for _, node := range c.Nodes {
		switch t := node.(type) {
		case *Empty:
			continue
		case *KV:
			lkey := strings.ToLower(t.Key)
			if lkey == lowerKey {
				return t, nil
			}
		default:
			return nil, fmt.Errorf("unknown Node type %v", t)
		}
	}
	return nil, nil
}

// GetAllKVs returns all the KV nodes that match the key.
func (c *Config) GetAllKVs(key string) ([]*KV, error) {
	lowerKey := strings.ToLower(key)
	all := []*KV(nil)
	for _, node := range c.Nodes {
		switch t := node.(type) {
		case *Empty:
			continue
		case *KV:
			lkey := strings.ToLower(t.Key)
			if lkey == lowerKey {
				all = append(all, t)
			}
		default:
			return nil, fmt.Errorf("unknown Node type %v", t)
		}
	}

	return all, nil
}

// String returns a string representation of the Config file.
func (c *Config) String() string {
	return c.marshal().String()
}

func (c *Config) marshal() *bytes.Buffer {
	var buf bytes.Buffer
	for i := range c.Nodes {
		buf.WriteString(c.Nodes[i].String())
		buf.WriteByte('\n')
	}
	return &buf
}
