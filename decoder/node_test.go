// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package decoder

import (
	"fmt"
)

func ExampleKV() {
	k := &KV{
		Key:      "key",
		Value:    "value",
		Comment:  "comment",
		position: Position{Line: 5, Col: 3},
	}
	fmt.Println(k.String())
	fmt.Println(k.Pos())
	// Output:
	// key value #comment
	// (5, 3)
}
