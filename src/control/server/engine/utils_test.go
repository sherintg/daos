//
// (C) Copyright 2021 Intel Corporation.
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
//

package engine

import (
	"testing"

	"github.com/daos-stack/daos/src/control/common"
	"github.com/pkg/errors"
)

func TestValidateLogMasks(t *testing.T) {
	for name, tc := range map[string]struct {
		masks  string
		expErr error
	}{
		"empty": {
			expErr: errors.New("empty log masks"),
		},
		"single level; no prefix": {
			masks: "DEBUG",
		},
		"single level; no prefix; unknown level": {
			masks:  "WARNING",
			expErr: errors.New("unknown log level"),
		},
		"single assignment": {
			masks: "mgmt=DEBUG",
		},
		"single level; single assignment": {
			masks: "ERR,mgmt=DEBUG",
		},
		"single level; single assignment; with space": {
			masks:  "ERR, mgmt=DEBUG",
			expErr: errors.New("illegal characters"),
		},
		"single level; single assignment; bad level": {
			masks: "ERR,mgmt=DEBUG",
		},
		"single assignment; single level": {
			masks:  "mgmt=DEBUG,ERR",
			expErr: errors.New("want PREFIX=LEVEL"),
		},
		"multiple assignment": {
			masks: "mgmt=DEBUG,bio=ERR",
		},
		"multiple assignment; bad format": {
			masks:  "mgmt=DEBUG,bio=ERR=",
			expErr: errors.New("want PREFIX=LEVEL"),
		},
		"multiple assignment; bad chars": {
			masks:  "mgmt=DEBUG,bio!=ERR",
			expErr: errors.New("illegal characters"),
		},
		"too long": {
			masks:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			expErr: errors.New("exceeds maximum length (1024>1023)"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			gotErr := ValidateLogMasks(tc.masks)
			common.CmpErr(t, tc.expErr, gotErr)
		})
	}
}
