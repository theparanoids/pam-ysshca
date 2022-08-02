// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package conf

import "testing"

func Test_parseBool(t *testing.T) {
	tests := []struct {
		name    string
		str     string
		want    bool
		wantErr bool
	}{
		{
			name: "yes",
			str:  "yes",
			want: true,
		},
		{
			name: "no",
			str:  "no",
			want: false,
		},
		{
			name:    "err",
			str:     "err",
			want:    false,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseBool(tt.str)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseBool() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseBool() got = %v, want %v", got, tt.want)
			}
		})
	}
}
