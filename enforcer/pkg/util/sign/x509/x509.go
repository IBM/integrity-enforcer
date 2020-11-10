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

package x509

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"path"
	"time"

	"github.com/IBM/integrity-enforcer/enforcer/pkg/common/common"
)

var startTimeInt int64

const (
	PEMTypePrivateKey  string = "RSA PRIVATE KEY"
	PEMTypePublicKey   string = "PUBLIC KEY"
	PEMTypeCertificate string = "CERTIFICATE"
)

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

func CreateCertificate(caName string, parentCertPemBytes, parentPrivateKeyPemBytes []byte) ([]byte, []byte, []byte, error) {
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
	if parentCertPemBytes != nil && parentPrivateKeyPemBytes != nil {
		parentCertBytes := PEMDecode(parentCertPemBytes, PEMTypeCertificate)
		parentCa, err = x509.ParseCertificate(parentCertBytes)
		if err != nil {
			return nil, nil, nil, err
		}
		parentPrivateKeyBytes := PEMDecode(parentPrivateKeyPemBytes, PEMTypePrivateKey)
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
	certPem := PEMEncode(caCertificate, PEMTypeCertificate)
	prvKeyPem := PEMEncode(prvKeyBytes, PEMTypePrivateKey)
	pubKeyPem := PEMEncode(pubKeyBytes, PEMTypePublicKey)
	return certPem, prvKeyPem, pubKeyPem, nil
}

func PEMEncode(content []byte, mode string) []byte {
	if mode != PEMTypePrivateKey && mode != PEMTypePublicKey && mode != PEMTypeCertificate {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: mode, Bytes: content})
}

func PEMDecode(pemBytes []byte, mode string) []byte {
	if mode != PEMTypePrivateKey && mode != PEMTypePublicKey && mode != PEMTypeCertificate {
		return nil
	}
	p, _ := pem.Decode(pemBytes)
	if p == nil {
		return nil
	}
	return p.Bytes
}

func loadPrivateKey(fpath string) (*rsa.PrivateKey, error) {
	keyPemBytes, err := ioutil.ReadFile(fpath)
	if err != nil {
		return nil, err
	}
	keyBytes := PEMDecode(keyPemBytes, PEMTypePrivateKey)
	private, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}
	return private, nil
}

func loadPublicKey(fpath string) (*rsa.PublicKey, error) {
	keyPemBytes, err := ioutil.ReadFile(fpath)
	if err != nil {
		return nil, err
	}
	keyBytes := PEMDecode(keyPemBytes, PEMTypePublicKey)
	public, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return nil, err
	}
	return public.(*rsa.PublicKey), nil
}

func loadCertificate(fpath string) (*x509.Certificate, error) {
	certPemBytes, err := ioutil.ReadFile(fpath)
	if err != nil {
		return nil, err
	}
	certBytes := PEMDecode(certPemBytes, PEMTypeCertificate)
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func GetPublicKeyFromCertificate(certPemBytes []byte) ([]byte, error) {
	certBytes := PEMDecode(certPemBytes, PEMTypeCertificate)
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

func GetSubjectFromCertificate(certPemBytes []byte) (pkix.Name, error) {
	certBytes := PEMDecode(certPemBytes, PEMTypeCertificate)
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return pkix.Name{}, err
	}
	return cert.Subject, nil
}

func ParseCertificate(certPemBytes []byte) (*x509.Certificate, error) {
	certBytes := PEMDecode(certPemBytes, PEMTypeCertificate)
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func GenerateSignature(msg, prvKeyPemBytes []byte) ([]byte, error) {
	prvKeyBytes := PEMDecode(prvKeyPemBytes, PEMTypePrivateKey)
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
		if !f.IsDir() && (path.Ext(f.Name()) == ".crt" || path.Ext(f.Name()) == ".pem") {
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

func VerifyCertificate(certPemBytes []byte, certPathList []string) (bool, string, error) {
	var reasonFail string
	var err error
	certBytes := PEMDecode(certPemBytes, PEMTypeCertificate)
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		reasonFail = fmt.Sprintf("failed to parse certificate: %s", err.Error())
		return false, reasonFail, fmt.Errorf(reasonFail)
	}

	roots := x509.NewCertPool()
	poolCerts := []*x509.Certificate{}
	for _, certPath := range certPathList {
		tmpCerts, err := loadCertDir(certPath)
		if err != nil {
			continue
		}
		poolCerts = append(poolCerts, tmpCerts...)
	}

	if err != nil {
		reasonFail = fmt.Sprintf("failed to load certificate pool: %s", err.Error())
		return false, reasonFail, fmt.Errorf(reasonFail)
	}
	for _, poolCert := range poolCerts {
		if !poolCert.Equal(cert) || isSelfSignedCert(cert) {
			roots.AddCert(poolCert)
		}
	}
	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	_, err = cert.Verify(opts)
	if err != nil {
		reasonFail = fmt.Sprintf("failed to verify certificate: %s", err.Error())
		return false, reasonFail, nil
	}

	return true, "", nil
}

func isSelfSignedCert(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawSubject, cert.RawIssuer)
}

func NewSignerInfoFromCert(cert *x509.Certificate) *common.SignerInfo {
	si := NewSignerInfoFromPKIXName(cert.Subject)
	si.SerialNumber = cert.SerialNumber
	return si
}

func NewSignerInfoFromPKIXName(dn pkix.Name) *common.SignerInfo {
	si := &common.SignerInfo{}

	if dn.Country != nil {
		si.Country = dn.Country[0]
	}
	if dn.Organization != nil {
		si.Organization = dn.Organization[0]
	}
	if dn.OrganizationalUnit != nil {
		si.OrganizationalUnit = dn.OrganizationalUnit[0]
	}
	if dn.Locality != nil {
		si.Locality = dn.Locality[0]
	}
	if dn.Province != nil {
		si.Province = dn.Province[0]
	}
	if dn.StreetAddress != nil {
		si.StreetAddress = dn.StreetAddress[0]
	}
	if dn.PostalCode != nil {
		si.PostalCode = dn.PostalCode[0]
	}
	if dn.CommonName != "" {
		si.CommonName = dn.CommonName
	}
	// if dn.SerialNumber != "" {
	// 	si.SerialNumber = dn.SerialNumber
	// }
	return si
}
