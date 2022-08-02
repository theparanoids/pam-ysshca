// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package decoder

import "fmt"

// Position is the position of a document element within the config file.
type Position struct {
	// Line and Col are both 1-indexed positions for the element's line number and
	// column number.
	Line int
	Col  int
}

// String returns the string of the position.
func (p Position) String() string {
	return fmt.Sprintf("(%d, %d)", p.Line, p.Col)
}

// Invalid returns true when the position is valid (negative or null).
func (p Position) Invalid() bool {
	return p.Line <= 0 || p.Col <= 0
}
