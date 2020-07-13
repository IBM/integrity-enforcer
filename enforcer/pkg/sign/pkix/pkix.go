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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path"
	"time"
)

var startTimeInt int64

func init() {
	startTimeInt = time.Now().UTC().UnixNano()
}

func GenerateKeyPair() (*rsa.PrivateKey, crypto.PublicKey, error) {
	privateCaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	publicCaKey := privateCaKey.Public()
	return privateCaKey, publicCaKey, nil
}

func CreateCertificate(caName string, parentCertBytes, parentPrivateKeyBytes []byte) ([]byte, []byte, []byte, error) {
	privateKey, publicCaKey, err := GenerateKeyPair()
	if err != nil {
		return nil, nil, nil, err
	}
	prvKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicCaKey)
	if err != nil {
		return nil, nil, nil, err
	}
	subjectCa := pkix.Name{
		CommonName: caName,
	}
	serialNumber := time.Now().UTC().UnixNano() - startTimeInt
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(serialNumber),
		Subject:               subjectCa,
		NotAfter:              time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		NotBefore:             time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	var parentCa *x509.Certificate
	var parentPrivateKey *rsa.PrivateKey

	// if parent data is given, create new cert using it.
	// otherwise, create self-signed cert
	if parentCertBytes != nil && parentPrivateKeyBytes != nil {
		parentCa, err = x509.ParseCertificate(parentCertBytes)
		if err != nil {
			return nil, nil, nil, err
		}
		parentPrivateKey, err = x509.ParsePKCS1PrivateKey(parentPrivateKeyBytes)
		if err != nil {
			return nil, nil, nil, err
		}
	} else {
		parentCa = ca
		parentPrivateKey = privateKey
	}

	caCertificate, err := x509.CreateCertificate(rand.Reader, ca, parentCa, publicCaKey, parentPrivateKey)
	if err != nil {
		return nil, nil, nil, err
	}
	return caCertificate, prvKeyBytes, pubKeyBytes, nil
}

func SaveCertificatePEM(fpath string, certificate []byte) error {
	var f *os.File
	f, err := os.Create(fpath)
	if err != nil {
		return err
	}
	err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	if err != nil {
		return err
	}
	err = f.Close()
	if err != nil {
		return err
	}
	return nil
}

func loadPrivateKey(fpath string) (*rsa.PrivateKey, error) {
	keyBytes, err := ioutil.ReadFile(fpath)
	if err != nil {
		return nil, err
	}
	private, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}
	return private, nil
}

func loadPublicKey(fpath string) (*rsa.PublicKey, error) {
	keyBytes, err := ioutil.ReadFile(fpath)
	if err != nil {
		return nil, err
	}
	public, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return nil, err
	}
	return public.(*rsa.PublicKey), nil
}

func loadCertificate(fpath string) (*x509.Certificate, error) {
	content, err := ioutil.ReadFile(fpath)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(content)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func saveCertificate(fpath string, certificate []byte) error {
	var f *os.File
	f, err := os.Create(fpath)
	if err != nil {
		return err
	}
	err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	if err != nil {
		return err
	}
	err = f.Close()
	if err != nil {
		return err
	}
	return nil
}

func GetPublicKeyFromCertificate(certBytes []byte) ([]byte, error) {
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, err
	}
	return pubKeyBytes, nil
}

func GetSubjectFromCertificate(certBytes []byte) (pkix.Name, error) {
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return pkix.Name{}, err
	}
	return cert.Subject, nil
}

func GenerateSignature(msg, prvKeyBytes []byte) ([]byte, error) {
	prvKey, err := x509.ParsePKCS1PrivateKey(prvKeyBytes)
	if err != nil {
		return nil, err
	}

	h := crypto.Hash.New(crypto.SHA256)
	h.Write([]byte(msg))
	msgHash := h.Sum(nil)

	sig, err := rsa.SignPKCS1v15(rand.Reader, prvKey, crypto.SHA256, msgHash)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func VerifySignature(msg, sig, pubKeyBytes []byte) (bool, string, error) {
	var reasonFail string
	var err error
	if msg == nil {
		reasonFail = "Message to be verified is empty"
		return false, reasonFail, fmt.Errorf(reasonFail)
	}
	if sig == nil {
		reasonFail = "Signature to be verified is empty"
		return false, reasonFail, fmt.Errorf(reasonFail)
	}

	h := crypto.Hash.New(crypto.SHA256)
	h.Write([]byte(msg))
	msgHash := h.Sum(nil)
	pubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		reasonFail := fmt.Sprintf("Error when loading public key; %s", err.Error())
		return false, reasonFail, fmt.Errorf(reasonFail)
	}
	err = rsa.VerifyPKCS1v15(pubKey.(*rsa.PublicKey), crypto.SHA256, msgHash, sig)
	if err != nil {
		reasonFail := fmt.Sprintf("Signature is invalid; %s", err.Error())
		return false, reasonFail, nil
	}
	return true, "", nil
}

func loadCertDir(certDir string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	files, err := ioutil.ReadDir(certDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get files from cert dir; %s", err.Error())
	}
	for _, f := range files {
		if !f.IsDir() && path.Ext(f.Name()) == ".crt" {
			fpath := path.Join(certDir, f.Name())
			cert, err := loadCertificate(fpath)
			if err != nil {
				return nil, fmt.Errorf("failed to load cert file \"%s\" ; %s", fpath, err.Error())
			}
			certs = append(certs, cert)
		}
	}
	return certs, nil
}

func VerifyCertificate(certBytes []byte, certDir string) (bool, string, error) {
	var reasonFail string
	var err error
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		reasonFail = fmt.Sprintf("failed to parse certificate: %s", err.Error())
		return false, reasonFail, fmt.Errorf(reasonFail)
	}

	roots := x509.NewCertPool()
	poolCerts, err := loadCertDir(certDir)
	if err != nil {
		reasonFail = fmt.Sprintf("failed to load certificate pool: %s", err.Error())
		return false, reasonFail, fmt.Errorf(reasonFail)
	}
	for _, poolCert := range poolCerts {
		if !poolCert.Equal(cert) {
			roots.AddCert(poolCert)
		}
	}
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	_, err = cert.Verify(opts)
	if err != nil {
		reasonFail = fmt.Sprintf("failed to verify certificate: %s", err.Error())
		return false, reasonFail, nil
	}
	// for _, c := range chains {
	// 	for _, ci := range c {
	// 		ciB, _ := json.Marshal(ci)
	// 		fmt.Println(string(ciB))
	// 	}
	// }

	return true, "", nil
}
