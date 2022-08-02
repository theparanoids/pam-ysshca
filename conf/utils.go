// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package conf

import (
	"fmt"
)

// ParseBool returns the boolean value represented by the string.
// It extends the acceptance values from strconv.ParseBool.
func parseBool(str string) (bool, error) {
	switch str {
	case "1", "t", "T", "true", "TRUE", "True",
		"y", "Y", "yes", "Yes", "YES":
		return true, nil
	case "0", "f", "F", "false", "FALSE", "False",
		"n", "N", "no", "No", "NO":
		return false, nil
	}
	return false, fmt.Errorf("parse %s error", str)
}
