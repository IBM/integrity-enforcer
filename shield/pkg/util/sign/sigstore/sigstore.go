package sigstore

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"

	"github.com/IBM/integrity-enforcer/shield/pkg/common"
	"github.com/IBM/integrity-enforcer/shield/pkg/util/mapnode"
	"github.com/IBM/integrity-enforcer/shield/pkg/util/sign"
	ishieldx509 "github.com/IBM/integrity-enforcer/shield/pkg/util/sign/x509"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/signature/payload"

	"github.com/IBM/integrity-enforcer/cmd/pkg/yamlsign"
)

const tmpDir = "/tmp"
const tmpOriginalFileName = "tmp.yaml"
const tmpSignedFileName = "tmp.yaml.signed"

const DefaultRootPemPath = "/tmp/root.pem"

const defaultRootPemURL = "https://raw.githubusercontent.com/sigstore/fulcio/main/config/ctfe/root.pem"

// ensure Verify() implements sign.VerifierFunc
var _ sign.VerifierFunc = Verify

func Verify(message, signature, certificate []byte, path string, opts map[string]string) (bool, *common.SignerInfo, string, error) {
	if imgVerifyStr, ok := opts["verifyWithImage"]; ok {
		imageVerifyEnabled, err := strconv.ParseBool(imgVerifyStr)
		if imageVerifyEnabled && err == nil {
			return imageVerify(path, opts)
		}
	}

	var bundle []byte
	if b, ok := opts["sigstoreBundle"]; ok && b != "" {
		bundle = []byte(b)
	}

	ok, err := verify(message, signature, certificate, bundle, &path)
	if err != nil {
		return false, nil, fmt.Sprintf("Failed to verify sigstore signature; %s", err.Error()), err
	} else if !ok {
		return false, nil, "Failed to verify sigstore signature; no error", nil
	}

	cert, err := ishieldx509.ParseCertificate(certificate)
	if err != nil {
		return false, nil, fmt.Sprintf("Failed to parse certificate; %s", err.Error()), err
	}
	signerInfo := ishieldx509.NewSignerInfoFromCert(cert)
	return true, signerInfo, "", nil
}

func verify(message, signature, certPem, bundle []byte, rootPemDir *string) (bool, error) {

	// clean up temporary files at the end of verification
	defer deleteTmpYamls()

	err := createTmpYamls(message, signature, certPem, bundle)
	if err != nil {
		return false, errors.Wrap(err, "error creating yaml files for verification")
	}

	cp, err := LoadCertPoolDir(*rootPemDir)
	if err != nil {
		return false, errors.Wrap(err, "error loading cert pool")
	}

	co := &cosign.CheckOpts{
		Claims: true,
		Tlog:   true,
		Roots:  cp,
	}

	fpath := path.Join(tmpDir, tmpSignedFileName)
	p, err := yamlsign.VerifyYaml(context.Background(), co, fpath)
	if err != nil {
		return false, err
	}
	if p == nil {
		return false, fmt.Errorf("signature does not match")
	}
	return true, nil
}

func imageVerify(path string, opts map[string]string) (bool, *common.SignerInfo, string, error) {
	var imageRef string
	if ir, ok := opts["imageRef"]; ok && ir != "" {
		imageRef = ir
	}
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return false, nil, fmt.Sprintf("Failed to parse image ref `%s`; %s", imageRef, err.Error()), err
	}
	cp, err := LoadCertPoolDir(path)
	if err != nil {
		return false, nil, fmt.Sprintf("error loading cert pool; %s", err.Error()), err
	}

	co := &cosign.CheckOpts{
		Claims: true,
		Tlog:   true,
		Roots:  cp,
	}

	rekorSever := cli.TlogServer()
	verified, err := cosign.Verify(context.Background(), ref, co, rekorSever)
	if err != nil {
		return false, nil, fmt.Sprintf("error occured while verifying image `%s`; %s", imageRef, err.Error()), err
	}
	if len(verified) == 0 {
		reasonFail := fmt.Sprintf("no verified signatures in the image `%s`; %s", imageRef, err.Error())
		return false, nil, reasonFail, errors.New(reasonFail)
	}
	var cert *x509.Certificate
	for _, vp := range verified {
		ss := payload.SimpleContainerImage{}
		err := json.Unmarshal(vp.Payload, &ss)
		if err != nil {
			continue
		}
		cert = vp.Cert
		break
	}
	signerInfo := ishieldx509.NewSignerInfoFromCert(cert)
	return true, signerInfo, "", nil
}

func LoadCert(certPath string) ([]*x509.Certificate, error) {
	pem, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	return cosign.LoadCerts(string(pem))
}

func LoadCertPoolDir(certDir string) (*x509.CertPool, error) {
	cp := x509.NewCertPool()

	files, err := ioutil.ReadDir(certDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get files from cert dir; %s", err.Error())
	}
	rootCertPath := ""
	for _, f := range files {
		if !f.IsDir() && (path.Ext(f.Name()) == ".crt" || path.Ext(f.Name()) == ".pem") {
			fpath := filepath.Join(certDir, f.Name())
			_, err := LoadCert(fpath)
			if err != nil {
				continue
			} else {
				rootCertPath = fpath
				break
			}

		}
	}
	if rootCertPath == "" {
		return nil, fmt.Errorf("failed to get root cert path from cert dir")
	}
	rootPem, err := ioutil.ReadFile(rootCertPath)
	if err != nil {
		return nil, errors.Wrap(err, "error reading root cert pem file")
	}
	ok := cp.AppendCertsFromPEM(rootPem)
	if !ok {
		return nil, fmt.Errorf("error creating root cert pool")
	}
	return cp, nil
}

func createTmpYamls(msg, sig, cert, bndl []byte) error {
	n1, err := mapnode.NewFromYamlBytes(msg)
	if err != nil {
		return err
	}

	annoMap := map[string]interface{}{}
	annoMap[common.MessageAnnotationKey] = base64encode(msg)
	annoMap[common.SignatureAnnotationKey] = base64encode(sig)
	annoMap[common.CertificateAnnotationKey] = base64encode(cert)
	if bndl != nil {
		annoMap[common.BundleAnnotationKey] = base64encode(bndl)
	}
	metadataMap := map[string]interface{}{}
	metadataMap["annotations"] = annoMap
	rootMap := map[string]interface{}{}
	rootMap["metadata"] = metadataMap

	n2, err := mapnode.NewFromMap(rootMap)
	if err != nil {
		return err
	}
	n, err := n1.Merge(n2)
	if err != nil {
		return err
	}
	f1path := path.Clean(path.Join(tmpDir, tmpOriginalFileName))

	err = ioutil.WriteFile(f1path, msg, 0644)
	if err != nil {
		return err
	}
	f2path := path.Clean(path.Join(tmpDir, tmpSignedFileName))
	signedYamlBytes := n.ToYaml()
	err = ioutil.WriteFile(f2path, []byte(signedYamlBytes), 0644)
	if err != nil {
		return err
	}
	return nil
}

func deleteTmpYamls() {
	f1path := path.Clean(path.Join(tmpDir, tmpOriginalFileName))
	f2path := path.Clean(path.Join(tmpDir, tmpSignedFileName))
	// ignore errors while deleting
	_ = os.Remove(f1path)
	_ = os.Remove(f2path)
}

func base64encode(in []byte) string {
	return base64.StdEncoding.EncodeToString(in)
}

func base64decode(in []byte) string {
	decBytes, err := base64.StdEncoding.DecodeString(string(in))
	if err != nil {
		return ""
	}
	dec := string(decBytes)
	return dec
}

func download(url string) ([]byte, error) {
	response, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func exists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}
