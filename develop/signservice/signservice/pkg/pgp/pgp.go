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
	"fmt"

	iepgp "github.com/IBM/integrity-enforcer/enforcer/pkg/sign"
)

const privateKeyringSecretPath = "/private-keyring-secret/secring.gpg"

func GenerateSignature(msg []byte, name string) ([]byte, error) {
	if msg == nil {
		return nil, fmt.Errorf("Message to be signed must not be null")
	}
	sig, _, err := iepgp.DetachSign(privateKeyringSecretPath, string(msg), name)
	if err != nil {
		return nil, err
	}
	return []byte(sig), nil
}
