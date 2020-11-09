//
// Copyright 2020 IBM Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package pgp

import (
	"os/user"
	"strings"
	"testing"
)

const testDefaultPublicRingPath = "~/.gnupg/pubring.gpg"
const testDefaultPrivateRingPath = "~/.gnupg/secring.gpg"

func getUserDir() string {
	usr, err := user.Current()
	userDir := ""
	if usr == nil || err != nil {
		userDir = "/root"
	} else {
		userDir = usr.HomeDir
	}
	return userDir
}

func getDefaultPublicRingPath() string {
	userDir := getUserDir()
	return strings.Replace(testDefaultPublicRingPath, "~", userDir, 1)
}

func getDefaultPrivateRingPath() string {
	userDir := getUserDir()
	return strings.Replace(testDefaultPrivateRingPath, "~", userDir, 1)
}

func TestSign(t *testing.T) {
	msg := `abc
`
	keyringPath := getDefaultPrivateRingPath()
	sig, reasonFail, err := DetachSign([]string{keyringPath}, msg, "")
	sigPrefix := `-----BEGIN PGP SIGNATURE-----`
	if !strings.HasPrefix(sig, sigPrefix) {
		t.Errorf("Failed to generate signature. sig: %s, reasonFail: %s, err: %s", sig, reasonFail, err)
	}
}

func TestVerify(t *testing.T) {
	msg := `abc
`
	secringPath := getDefaultPrivateRingPath()
	sig, reasonFail, err := DetachSign([]string{secringPath}, msg, "")
	if reasonFail != "" || err != nil {
		t.Errorf("Failed to generate signature. sig: %s, reasonFail: %s, err: %s", sig, reasonFail, err)
	}

	keyringPath := getDefaultPublicRingPath()
	verified, reasonFail, signer, err := VerifySignature([]string{keyringPath}, msg, sig)

	if !verified {
		t.Errorf("Failed to verify. verified: %t, reasonFail: %s, signaer: %s, err: %s", verified, reasonFail, signer, err)
	}
}
