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

package custom

import (
	"errors"

	"github.com/IBM/integrity-enforcer/shield/pkg/common"
	"github.com/IBM/integrity-enforcer/shield/pkg/util/sign"
)

// This is a sample implementation of custom verification.
// All functions that implements "sign.VerifierFunc" can be called in sign_verifier.go in "shield" package.
// About how to call your verify function, please refer to sign_verifier.go .

var ensureVerifyFunc sign.VerifierFunc

func init() {
	// if a build error is found here, your custom Verify() function
	// does not match with type of sign.VerifeirFunc
	ensureVerifyFunc = Verify
}

func Verify(message, signature, certificate []byte, path string, opts map[string]string) (bool, *common.SignerInfo, string, error) {
	var signerInfo *common.SignerInfo
	ok, err := verify(message, signature, certificate, path)
	return ok, signerInfo, "Failed to verify signature with custom Verify() function", err
}

func verify(message, signature, certificate []byte, path string) (bool, error) {
	return false, errors.New("This function is not implemented yet...")
}
