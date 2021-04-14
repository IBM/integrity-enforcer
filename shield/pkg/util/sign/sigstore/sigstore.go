package sigstore

import (
	"context"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	// gyaml "github.com/ghodss/yaml"

	"github.com/IBM/integrity-enforcer/shield/pkg/common"
	"github.com/IBM/integrity-enforcer/shield/pkg/util/mapnode"
	"github.com/pkg/errors"

	"github.com/gajananan/cosign/pkg/cosign"
)

const tmpDir = "/tmp"
const tmpOriginalFileName = "tmp.yaml"
const tmpSignedFileName = "tmp.yaml.signed"

const DefaultRootPemPath = "/tmp/root.pem"

//go:embed fulcio.pem
var defaultRootPem string

func init() {
	_ = ioutil.WriteFile(DefaultRootPemPath, []byte(defaultRootPem), 0644)
}

func Verify(message, signature, certPem []byte, rootPemPath *string) (bool, error) {

	defer deleteTmpYamls()

	err := createTmpYamls(message, signature, certPem)
	if err != nil {
		return false, errors.Wrap(err, "error creating yaml files for verification")
	}

	cp := x509.NewCertPool()

	if rootPemPath == nil {
		var pemPath string
		pemPath = DefaultRootPemPath
		rootPemPath = &pemPath
	}
	rootPem, err := ioutil.ReadFile(*rootPemPath)
	if err != nil {
		return false, errors.Wrap(err, "error reading root cert pem file")
	}
	ok := cp.AppendCertsFromPEM(rootPem)
	if !ok {
		return false, fmt.Errorf("error creating root cert pool")
	}

	co := cosign.CheckOpts{
		Tlog:  true,
		Roots: cp,
	}

	fpath := path.Join(tmpDir, tmpSignedFileName)
	p, err := cosign.Verify(context.Background(), nil, co, fpath)
	if err != nil {
		return false, err
	}
	if len(p) == 0 {
		return false, fmt.Errorf("signature does not match")
	}
	return true, nil
}

func LoadCert(certPath string) ([]*x509.Certificate, error) {
	pem, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	return cosign.LoadCerts(string(pem))
}

func createTmpYamls(msg, sig, cert []byte) error {
	n1, err := mapnode.NewFromYamlBytes(msg)
	if err != nil {
		return err
	}

	annoYamlBytes := fmt.Sprintf(`
metadata:
  annotations:
    %s: %s
    %s: %s
    %s: %s
`, common.MessageAnnotationKey, base64encode(msg),
		common.SignatureAnnotationKey, base64encode(sig),
		common.CertificateAnnotationKey, base64encode(cert))

	n2, err := mapnode.NewFromYamlBytes([]byte(annoYamlBytes))
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
