// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package challenge

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"golang.org/x/crypto/ssh"
)

// Data defines format to be used for ssh challenge-response.
type Data struct {
	// Data is the random data for the private key to sign.
	Data []byte
	// Signature is the signature of random data that signed by the private key.
	Signature ssh.Signature
}

// NewData creates a Data.
func NewData() (*Data, error) {
	data := make([]byte, 64)
	if _, err := rand.Read(data); err != nil {
		return nil, err
	}
	return &Data{
		Data: data,
	}, nil
}

// Marshal returns the base64 encoded JSON for Data.
func (c *Data) Marshal() ([]byte, error) {
	cBytes, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return []byte(base64.StdEncoding.EncodeToString(cBytes)), nil
}

// Unmarshal parses the base64 encoded JSON data and stores the result in the challenge data.
func (c *Data) Unmarshal(data []byte) error {
	cBytes, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return err
	}
	return json.Unmarshal(cBytes, c)
}

// Challenge encapsulates the logic to generate challenge data and to verify a challenge response.
type Challenge struct {
	data *Data
	key  ssh.PublicKey
}

// NewChallenge returns a new challenge.
func NewChallenge(key ssh.PublicKey) (*Challenge, error) {
	c, err := NewData()
	if err != nil {
		return nil, err
	}
	return &Challenge{
		data: c,
		key:  key,
	}, err
}

// ChallengeRequest requests the serialized data of the challenge data.
func (c *Challenge) ChallengeRequest() ([]byte, error) {
	cBytes, err := c.data.Marshal()
	if err != nil {
		return nil, err
	}
	return cBytes, nil
}

// VerifyResponse returns nil if the public key of the challenge can verify the response data.
func (c *Challenge) VerifyResponse(resp string) error {
	respCh := &Data{}
	if err := respCh.Unmarshal([]byte(resp)); err != nil {
		return err
	}
	return c.key.Verify(c.data.Data, &respCh.Signature)
}
