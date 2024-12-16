// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package decoder

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func loadFile(t *testing.T, filename string) []byte {
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestDecode(t *testing.T) {
	var files = []string{"testdata/config_01.conf", "testdata/config_02.conf"}
	for _, filename := range files {
		data := loadFile(t, filename)
		cfg, err := Decode(data)
		if err != nil {
			t.Fatal(err)
		}
		got := cfg.String()
		want := string(data)
		if got != want {
			t.Errorf("got != data: out: %q\nwant: %q", got, want)
		}
	}
}

func TestDecode_LeadingSpace(t *testing.T) {
	var file = "testdata/config_03.conf"
	data := loadFile(t, file)
	cfg, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(cfg.String())
	want := strings.TrimSpace(string(data))
	if got != want {
		t.Errorf("got != data: out: %q\nwant: %q", got, want)
	}
}

func TestGet(t *testing.T) {
	data := loadFile(t, "testdata/config_01.conf")
	cfg, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := cfg.Get("AuthorizedKeysFile")
	want := "/etc/ssh/sample3.pub"
	if got != want {
		t.Errorf("Get() got = %v, want %v", got, want)
	}
}

func TestGetAll(t *testing.T) {
	data := loadFile(t, "testdata/config_01.conf")
	cfg, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := cfg.GetAll("filter")
	want := []string{"/etc/filter-example1", "/etc/filter-example2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Get() got = %v, want %v", got, want)
	}
}
