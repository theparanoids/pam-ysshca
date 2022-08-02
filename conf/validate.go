// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package conf

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/theparanoids/pam-ysshca/msg"
)

// validateFiles validates the file permission of the list of files.
func validateFiles(files []string, owner int, require os.FileMode, deny os.FileMode) []string {
	var result []string
	for _, file := range files {
		if err := validateFilePermission(file, owner, require, deny); err != nil {
			if strings.Contains(err.Error(), "no such file or directory") {
				msg.Printlf(msg.DEBUG, "File %s doesn't exist, skipping permission check: %v", file, err)
			} else {
				msg.Printlf(msg.WARN, "File %s doesn't pass the permission check: %v", file, err)
			}
			continue
		}
		result = append(result, file)
	}
	return result
}

// validateFilePermission check whether the file have suitable ownership or permissions.
// uid is the uid of suitable owner, -1 means anyone
// require is the permission required, 0000 requires nothing
// deny is the permission we don't want, 0000 denies nothing
func validateFilePermission(path string, owner int, require os.FileMode, deny os.FileMode) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return err
	}
	if owner != -1 && stat.Uid != uint32(owner) {
		return fmt.Errorf("unsuitable owner: %d, expected owner: %d", stat.Uid, uint32(owner))
	}
	if info.Mode()&require != require {
		return fmt.Errorf("require permission: %s", require)
	}
	if info.Mode()&deny != 0000 {
		return fmt.Errorf("deny permission: %s", deny)
	}
	return nil
}
