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
	"encoding/base64"
	"io/ioutil"
	"os"
	"testing"
)

// const testDefaultPublicRingPath = "~/.gnupg/pubring.gpg"
// const testDefaultPrivateRingPath = "~/.gnupg/secring.gpg"
const testPubringData = "mQENBF+0ogoBCADiOMDUUXI/dnPjSj1GTJ5pNv6GTzxEEkFNSjzskTyGPwE+D14yiZ74BwIsa+n0hZHWfUeGP41oxMxBsTx+F7AHb4i/7SXg8K6Qg07xJgy1Q5fV7m7EliVZ9Xso5VqrEyTaa8ipC2DCvSYkWUD3fKR3W5dh18qqr6RCSkMltiIb2IG9DNQSHm9KtxR0olgxl6glB20a+W9yoy9Jwgat8RepyBumpKEcAF0+Kz9jR+zVepeagAdXb4d+BCnP92y9lb1sPBd0p0EepK3G9RVg2dgV8Lt6nmPRZRQ1ujBG3SS7Gk/VGtUGzexAFw5OrIiQ23FXfIdMBVWqmliZG06AmfaxABEBAAG0IlRlc3RTaWduZXIgPHNpZ25lckBlbnRlcnByaXNlLmNvbT6JAVQEEwEIAD4WIQRAV4GytKYvpEfFpEj6TtJdLICAvwUCX7SiCgIbAwUJA8JnAAULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRD6TtJdLICAv8+nB/9e4zKZIumLS4Y3e9IFkAry/Cfofi1TAKz1X8eh3ifIaBGwTxNgT4ef5y+L2ofHAWBgb/W/ymbaryuL97l+M/c2M7aijygOz3WLY2CNtBSWnU7D4HJH+pvKNxcSvQ0cDLRBakWxX/CqwjI+71n1ug037XR4Kb+WfwfcBp5oA2EQOxKjbLj+II8N8CTj/YE0YPF4NaH3OnArlUjzGVw7JWpYIYCW/xKdEe/lOjH6fheZvMMLIwEXUPiTYpI7UHmLyzBaCQEMtZEML/Fgm81KHKvZJcnUGXC4At4wFFvi+vbUy5ZEeQ+E3Sy40mTFkwd7hrx3VdK1v6Za9RNXL17Q6ICWuQENBF+0ogoBCADiTdFnG4F8ZkszDhCQtMpuXLG6C43duX3Upfb8q4htp+rpDcy3esacNQu0jVJpnSsDk3F7tRpw+PeCTDKpYM6XA6MiHjmtdF+lE76Ay1Q15brc78B/sh9v0N4RmEWe38xbxjqDf5o1dMoqHS/cR16pRURJIJhIkvoi28VvCpYhVuKXKz/rC+gox00ZvaQAx8dvgqTvRmpm1/dCayRWdszPsjqGB0rRz9muJbV9HDdPP0p+JCJe/JO3RFpJpVfmxGzx9fRyLc8lYJkgdJoB1Vwpk95KYHqXkMv5F5liWGofVE6VIAdYTbammicl7mnXo+RnpwnFPgC86DoGcZpyjJEZABEBAAGJATwEGAEIACYWIQRAV4GytKYvpEfFpEj6TtJdLICAvwUCX7SiCgIbDAUJA8JnAAAKCRD6TtJdLICAv1eFCACYgkgPbhTxVouKevXr/CtDbZR6GW7gFEHpT1PFVxJIjiMSD2xJv8oBswdp+JOffpJCy+B1QgIHI0BphjU33nYRfq/cUStLIh6xEfrnsZLGx0pjuSvAWtNwrObbWeQSSh1P+juUgzG8BpUPsjp8FIV/RmV0HO3LFN9TpLhW1mtziU4kPyBgnqaLc2P4JHVKf/RhBl15qmxrBc0IsepT+WTrTEjflfAW2GUjbQoAsLs/0qcOowwKOC7FZqxJ7NUuQRp0Kzssx/OPIzZ90uXEqxNd3YVhw0IDf+sWpdOji/jIAfAm+nkQ2oxzup1oUAqCqM5HoTpSt//7By+gJXZofa+8"
const testPubringPath = "./keyring-secret"
const testMessage = "YXBpVmVyc2lvbjogdjEKa2luZDogQ29uZmlnTWFwCm1ldGFkYXRhOgogIG5hbWU6IHRlc3QtY29uZmlnbWFwMgpkYXRhOgogIGNvbG9yOiBibHVl"
const testSiganture = "LS0tLS1CRUdJTiBQR1AgU0lHTkFUVVJFLS0tLS0KCmlRRktCQUFCQ0FBMEZpRUVRRmVCc3JTbUw2Ukh4YVJJK2s3U1hTeUFnTDhGQWwrMHNJc1dISE5wWjI1bGNrQmwKYm5SbGNuQnlhWE5sTG1OdmJRQUtDUkQ2VHRKZExJQ0F2NUZCQi85aEFKdmNHRTIvUjRUNDZPbnp6eklCbExYYQo0ZjRwYVRicmtYQitKUHRvL3NaRS9Pb2hqWWVJTmlhaEZuNUQ4VHhKQmpxcTVTQWwrekNzVERHdnBVNUdmdDdTCkZsM1cyZ29BVThaU2c4RS9ySHlWSmJudkhvWmdkZEZlWEhhSm54cjA2V0ZpRUswVUNiZTU0L0c4TGgzTFdPN0cKV2k5VHN2S1VhaUNzMlF5dUZYVE04VXpVTTJXR1F5NDd0MU9mNU5RV1ZFZmtjWXAyNDhNYUwzTHl2a2tvc2hONwpiYURhRVU4YWNPYkxIaUo4ZllXZS81ZVBRZkJYQWNJczg1SW15OFVXQXlKbmtha2pvaXZNcTFZL3lya1UxNytKCmp5MjdrS2hmdGhBc2lCTUR3U283YTJBbXpZaDlXcTNrMWxFOXZpaEw3N1QxN091dnJyTVM5djcvalFoaAo9TDlpNAotLS0tLUVORCBQR1AgU0lHTkFUVVJFLS0tLS0K"

// func getUserDir() string {
// 	usr, err := user.Current()
// 	userDir := ""
// 	if usr == nil || err != nil {
// 		userDir = "/root"
// 	} else {
// 		userDir = usr.HomeDir
// 	}
// 	return userDir
// }

// func getDefaultPublicRingPath() string {
// 	userDir := getUserDir()
// 	return strings.Replace(testDefaultPublicRingPath, "~", userDir, 1)
// }

// func getDefaultPrivateRingPath() string {
// 	userDir := getUserDir()
// 	return strings.Replace(testDefaultPrivateRingPath, "~", userDir, 1)
// }

// func TestSign(t *testing.T) {
// 	msg := `abc
// `
// 	keyringPath := getDefaultPrivateRingPath()
// 	sig, reasonFail, err := DetachSign([]string{keyringPath}, msg, "")
// 	sigPrefix := `-----BEGIN PGP SIGNATURE-----`
// 	if !strings.HasPrefix(sig, sigPrefix) {
// 		t.Errorf("Failed to generate signature. sig: %s, reasonFail: %s, err: %s", sig, reasonFail, err)
// 	}
// }

func base64decode(str string) string {
	decBytes, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return ""
	}
	dec := string(decBytes)
	return dec
}

func TestVerify(t *testing.T) {

	pubringDecodedData := base64decode(testPubringData)
	decodedMessage := base64decode(testMessage)
	decodedSiganture := base64decode(testSiganture)
	err := ioutil.WriteFile(testPubringPath, []byte(pubringDecodedData), 0644)
	if err != nil {
		t.Error(err)
	}

	verified, reasonFail, signer, err := VerifySignature([]string{testPubringPath}, decodedMessage, decodedSiganture)

	if !verified {
		t.Errorf("Failed to verify. verified: %t, reasonFail: %s, signaer: %s, err: %s", verified, reasonFail, signer, err)
	}
	_ = os.Remove(testPubringPath)
}
