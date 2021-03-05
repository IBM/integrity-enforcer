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
	"os"
	"path/filepath"
	"strings"

	"github.com/IBM/integrity-enforcer/shield/pkg/util/logger"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

type Signer struct {
	Email              string `json:"email,omitempty"`
	Name               string `json:"name,omitempty"`
	Comment            string `json:"comment,omitempty"`
	Uid                string `json:"uid,omitempty"`
	Country            string `json:"country,omitempty"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizationalUnit,omitempty"`
	Locality           string `json:"locality,omitempty"`
	Province           string `json:"province,omitempty"`
	StreetAddress      string `json:"streetAddress,omitempty"`
	PostalCode         string `json:"postalCode,omitempty"`
	CommonName         string `json:"commonName,omitempty"`
	SerialNumber       string `json:"serialNumber,omitempty"`
	Fingerprint        []byte `json:"finerprint"`
}

func NewSignerFromUserId(uid *packet.UserId) *Signer {
	return &Signer{
		Email:   uid.Email,
		Name:    uid.Name,
		Comment: uid.Comment,
	}
}

func (s *Signer) EqualTo(s2 *Signer) bool {
	emailOk := (s.Email == s2.Email)
	nameOk := (s.Name == s2.Name)
	commentOk := (s.Comment == s2.Comment)
	return emailOk && nameOk && commentOk
}

func GetFirstIdentity(signer *openpgp.Entity) *openpgp.Identity {
	for _, idt := range signer.Identities {
		return idt
	}
	return nil
}

func VerifySignature(keyPath string, msg, sig string) (bool, string, *Signer, []byte, error) {
	if msg == "" {
		return false, "Message to be verified is empty", nil, nil, nil
	}
	if sig == "" {
		return false, "Signature to be verified is empty", nil, nil, nil
	}
	cfgReader := strings.NewReader(msg)
	sigReader := strings.NewReader(sig)

	if keyRing, err := LoadKeyRing(keyPath); err != nil {
		return false, "Error when loading key ring", nil, nil, err
	} else if signer, err := openpgp.CheckArmoredDetachedSignature(keyRing, cfgReader, sigReader); signer == nil {
		logger.Debug("msg:", msg)
		logger.Debug("sig:", sig)
		if err != nil {
			logger.Error("Signature verification error:", err.Error())
		}
		return false, "Signed by unauthrized subject (signer is not in public key), or invalid format signature", nil, nil, nil
	} else {
		idt := GetFirstIdentity(signer)
		fingerprint := ""
		if signer.PrimaryKey != nil {
			fingerprint = fmt.Sprintf("%X", signer.PrimaryKey.Fingerprint)
		}
		return true, "", NewSignerFromUserId(idt.UserId), []byte(fingerprint), nil
	}
}

func MatchIdentity(idt *openpgp.Identity, signer string) bool {
	if strings.Contains(idt.UserId.Email, signer) {
		return true
	} else if strings.Contains(idt.UserId.Name, signer) {
		return true
	} else if strings.Contains(idt.UserId.Comment, signer) {
		return true
	}
	return false
}

func GetSignersFromEntityList(keyring openpgp.EntityList) []*Signer {
	signers := []*Signer{}
	keys := EntityListToSlice(keyring)
	for _, key := range keys {
		idt := GetFirstIdentity(key)
		signer := NewSignerFromUserId(idt.UserId)
		if signer != nil {
			signers = append(signers, signer)
		}
	}
	return signers
}

func FindSignerKey(keyring openpgp.EntityList, signer string) *openpgp.Entity {
	keys := keyring.DecryptionKeys()
	for _, key := range keys {
		ent := key.Entity
		idt := GetFirstIdentity(ent)
		if MatchIdentity(idt, signer) {
			return ent
		}
	}
	return nil
}

func EntityListToSlice(keyring openpgp.EntityList) []*openpgp.Entity {
	entSlice := []*openpgp.Entity{}
	for _, ent := range keyring {
		entSlice = append(entSlice, ent)
	}
	return entSlice
}

// func DetachSign(keyPathList []string, msg string, signer string) (string, string, error) {
// 	if msg == "" {
// 		return "", "Message to be signed is empty", nil
// 	}
// 	sig := ""
// 	msgReader := strings.NewReader(msg)
// 	sigWriter := bytes.NewBufferString(sig)

// 	keyRing, err := LoadKeyRing(keyPathList)
// 	if err != nil {
// 		return "", "Error when loading key ring", err
// 	}
// 	var signerKey *openpgp.Entity
// 	if signer == "" {
// 		signerKey = keyRing[0]
// 	} else {
// 		signerKey = FindSignerKey(keyRing, signer)
// 	}
// 	if signerKey == nil {
// 		reasonFail := fmt.Sprintf("No signer match with the specified signer expression: %s", signer)
// 		return "", reasonFail, errors.New(reasonFail)
// 	}

// 	err = openpgp.ArmoredDetachSignText(sigWriter, signerKey, msgReader, nil)
// 	if err != nil {
// 		return "", "Error when signing", err
// 	}

// 	return sigWriter.String(), "", nil
// }

func LoadKeyRing(keyPath string) (openpgp.EntityList, error) {
	entities := []*openpgp.Entity{}
	var retErr error
	kpath := filepath.Clean(keyPath)
	if keyRingReader, err := os.Open(kpath); err != nil {
		retErr = err
	} else {
		tmpList, err := openpgp.ReadKeyRing(keyRingReader)
		if err != nil {
			retErr = err
		}
		for _, tmp := range tmpList {
			entities = append(entities, tmp)
		}
	}
	return openpgp.EntityList(entities), retErr
}
