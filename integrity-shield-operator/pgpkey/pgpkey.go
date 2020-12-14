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

package pgpkey

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"golang.org/x/crypto/openpgp"
)

const defaultPath = "/tmp/"
const defaultPublicKeyringName = "pubring.gpg"
const defaultPrivateKeyringName = "secring.gpg"

type Keyring struct {
	Public  map[string][]byte
	Private map[string][]byte
}

func GetPublicKeyringName() string {
	return defaultPublicKeyringName
}

func CreateEntities(signers []string) ([]*openpgp.Entity, error) {
	entList := []*openpgp.Entity{}
	for _, signer := range signers {
		ent, err := openpgp.NewEntity(signer, signer, signer, nil)
		if err != nil {
			return nil, err
		}
		entList = append(entList, ent)
	}
	return entList, nil
}

func getFirstIdentity(idts map[string]*openpgp.Identity) *openpgp.Identity {
	for k := range idts {
		return idts[k]
	}
	return nil
}

func keyInList(key string, list []string) bool {
	for _, item := range list {
		if key == item {
			return true
		}
	}
	return false
}

func GenerateKeyring(signers []string, invalidSigners []string) (*Keyring, error) {
	err := CreateKeyringFile(defaultPath, signers, invalidSigners)
	if err != nil {
		return nil, err
	}
	keyring, err := GetKeyringValue(defaultPath)
	if err != nil {
		return nil, err
	}
	return keyring, nil
}

func CreateKeyringFile(path string, signers []string, invalidSigners []string) error {
	allSigners := []string{}
	allSigners = append(allSigners, signers...)
	allSigners = append(allSigners, invalidSigners...)

	entList, err := CreateEntities(allSigners)
	if err != nil {
		return fmt.Errorf("Error in creating entities for public keyring; %s", err.Error())
	}

	secfile, err := os.Create(path + defaultPrivateKeyringName)
	if err != nil {
		return fmt.Errorf("Error in creating private keyring file; %s", err.Error())
	}
	defer func() {
		_ = secfile.Close()
	}()

	for _, ent := range entList {
		err := ent.SerializePrivate(secfile, nil)
		if err != nil {
			return fmt.Errorf("Error in serializing entities for private keyring; %s", err.Error())
		}
	}

	pubfile, err := os.Create(path + defaultPublicKeyringName)
	if err != nil {
		return fmt.Errorf("Error in creating public keyring file; %s", err.Error())
	}
	defer func() {
		_ = pubfile.Close()
	}()

	for _, ent := range entList {
		idt := getFirstIdentity(ent.Identities)
		if keyInList(idt.UserId.Email, invalidSigners) {
			continue
		}
		err := ent.Serialize(pubfile)
		if err != nil {
			return fmt.Errorf("Error in serializing entities for public keyring; %s", err.Error())
		}
	}

	return nil
}

func GetKeyringValue(path string) (*Keyring, error) {

	rawPubFilePath := filepath.Join(path, filepath.Clean(defaultPublicKeyringName))
	rawPub, err := ioutil.ReadFile(rawPubFilePath)
	if err != nil {
		return nil, fmt.Errorf("Error in getting value of public keyring; %s", err.Error())
	}

	rawSecFilePath := filepath.Join(path, filepath.Clean(defaultPrivateKeyringName))
	rawSec, err := ioutil.ReadFile(rawSecFilePath)
	if err != nil {
		return nil, fmt.Errorf("Error in getting value private keyring; %s", err.Error())
	}

	keyring := &Keyring{
		Public:  map[string][]byte{defaultPublicKeyringName: []byte(rawPub)},
		Private: map[string][]byte{defaultPrivateKeyringName: []byte(rawSec)},
	}
	return keyring, nil
}
