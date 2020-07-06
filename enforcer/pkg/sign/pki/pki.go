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

package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

func GenerateKeyPair() (*rsa.PrivateKey, crypto.PublicKey, error) {
	privateCaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	publicCaKey := privateCaKey.Public()
	return privateCaKey, publicCaKey, nil
}

func CreateCACertificate(caName string, parentCertBytes []byte) ([]byte, []byte, []byte, error) {
	privateCaKey, publicCaKey, err := GenerateKeyPair()
	if err != nil {
		return nil, nil, nil, err
	}
	prvKeyBytes := x509.MarshalPKCS1PrivateKey(privateCaKey)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicCaKey)
	if err != nil {
		return nil, nil, nil, err
	}
	subjectCa := pkix.Name{
		CommonName: caName,
	}
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               subjectCa,
		NotAfter:              time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		NotBefore:             time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	parentCa, err := x509.ParseCertificate(parentCertBytes)

	caCertificate, err := x509.CreateCertificate(rand.Reader, caTpl, parentCa, publicCaKey, privateCaKey)
	if err != nil {
		return nil, nil, nil, err
	}
	return caCertificate, prvKeyBytes, pubKeyBytes, nil
}

func CreateSignerCertificate(signerName string, caCertificate, prvCaKeyBytes []byte) ([]byte, []byte, []byte, error) {
	caTpl, err := x509.ParseCertificate(caCertificate)
	if err != nil {
		return nil, nil, nil, err
	}
	privateCaKey, err := x509.ParsePKCS1PrivateKey(prvCaKeyBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	privateSignerKey, publicSignerKey, err := GenerateKeyPair()
	if err != nil {
		return nil, nil, nil, err
	}
	prvKeyBytes := x509.MarshalPKCS1PrivateKey(privateSignerKey)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicSignerKey)
	if err != nil {
		return nil, nil, nil, err
	}
	subjectSigner := pkix.Name{
		CommonName: signerName,
	}
	signerTpl := &x509.Certificate{
		SerialNumber: big.NewInt(123),
		Subject:      subjectSigner,
		NotAfter:     time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		NotBefore:    time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	signerCertificate, err := x509.CreateCertificate(rand.Reader, signerTpl, caTpl, publicSignerKey, privateCaKey)
	if err != nil {
		return nil, nil, nil, err
	}
	return signerCertificate, prvKeyBytes, pubKeyBytes, nil
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

func loadPrivateKey(keyBytes []byte) (*rsa.PrivateKey, error) {
	private, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}
	return private, nil
}

func loadPublicKey(keyBytes []byte) (*rsa.PublicKey, error) {
	public, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return nil, err
	}
	return public.(*rsa.PublicKey), nil
}

func GenerateSignature(msg, prvKeyBytes []byte) ([]byte, error) {
	prvKey, err := loadPrivateKey(prvKeyBytes)
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

func VerifySignature(msg, sig, pubKeyBytes []byte) (bool, error) {
	h := crypto.Hash.New(crypto.SHA256)
	h.Write([]byte(msg))
	msgHash := h.Sum(nil)
	pubKey, err := loadPublicKey(pubKeyBytes)
	if err != nil {
		return false, err
	}
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, msgHash, sig)
	if err != nil {
		return false, err
	}
	return true, nil
}

func VerifyCertificate(certBytes []byte, caCertBytes []byte) ([][]*x509.Certificate, error) {
	roots := x509.NewCertPool()

	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: " + err.Error())
	}

	roots.AddCert(caCert)

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: " + err.Error())
	}

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	chains, err := cert.Verify(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to verify certificate: " + err.Error())
	}

	return chains, nil
}
