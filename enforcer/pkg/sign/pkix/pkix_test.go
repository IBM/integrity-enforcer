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

package pkix

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestEndToEndCAVerification(t *testing.T) {

	rootCert, rootPrvKeyBytes, _, err := CreateCertificate("DegiCert Root CA", nil, nil)
	if err != nil {
		t.Error(err)
	}
	adminCertificate, adminPrvKeyBytes, _, err := CreateCertificate("CISO CSS Certificate", rootCert, rootPrvKeyBytes)
	if err != nil {
		t.Error(err)
	}
	serviceCertificate, servicePrvKeyBytes, servicePubKeyBytes, err := CreateCertificate("Services Team HSM partition Certificate", adminCertificate, adminPrvKeyBytes)
	if err != nil {
		t.Error(err)
	}

	testPrivateKeyPath := "./test-ie-private.key"
	testPublicKeyPath := "./test-ie-public.key"
	testCertPoolDir := "./"
	testRootCert := testCertPoolDir + "test-root.crt"
	testAdminCert := testCertPoolDir + "test-admin.crt"
	testServiceCert := testCertPoolDir + "test-service.crt"

	ioutil.WriteFile(testPrivateKeyPath, servicePrvKeyBytes, 0644)
	ioutil.WriteFile(testPublicKeyPath, servicePubKeyBytes, 0644)
	ioutil.WriteFile(testRootCert, rootCert, 0644)
	ioutil.WriteFile(testAdminCert, adminCertificate, 0644)
	ioutil.WriteFile(testServiceCert, serviceCertificate, 0644)

	msg := []byte("abc")

	sig, err := GenerateSignature(msg, servicePrvKeyBytes)
	if err != nil {
		t.Error(err)
	}

	sigOk, _, err := VerifySignature(msg, sig, servicePubKeyBytes)
	if err != nil {
		t.Error(err)
	}
	t.Log("signature verification result: %s", sigOk)

	certOk, _, err = VerifyCertificate(serviceCertificate, testCertPoolDir)
	if err != nil {
		t.Error(err)
	}
	t.Log("certificate verification result: %s", certOk)

	os.Remove(testPrivateKeyPath)
	os.Remove(testPublicKeyPath)
	os.Remove(testRootCert)
	os.Remove(testAdminCert)
	os.Remove(testServiceCert)
}
