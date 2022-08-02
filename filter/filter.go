// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package filter

const EmbeddedPrefix = "embedded:"

// Doer is an interface implements Filter function.
type Doer interface {
	// Filter filters the certificates.
	Filter([]byte) []byte
}
