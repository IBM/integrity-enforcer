// The code in this file were adapted from the following original source to test sign YAML files.
// The original source: https://github.com/sigstore/cosign/blob/main/test/e2e_test.go

package cli

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/cosign"
)

var (
	ishiedlRoot           = os.Getenv("ISHIELD_REPO_ROOT")
	testPayloadPath       = ishiedlRoot + "/cmd/test/data/test_configmap.yaml"
	testSignedPayloadPath = ishiedlRoot + "/cmd/test/data/test_configmap.yaml.signed"
)

var passFunc = func(_ bool) ([]byte, error) {
	return []byte("sign yaml test"), nil

}
var signYaml = func(keyRef, payloadPath string) error {
	cmd := SignYamlCommand{
		KeyRef:      keyRef,
		PayloadPath: payloadPath,
		Sk:          false,
		Pf:          passFunc,
	}
	return cmd.Exec(context.Background(), nil)
}

var signYamlVerify = func(keyRef, payloadPath string) error {
	cmd := VerifyYamlCommand{
		CheckClaims: true,
		KeyRef:      keyRef,
		Sk:          false,
		Output:      "json",
		PayloadPath: payloadPath,
	}
	return cmd.Exec(context.Background(), nil)
}

func TestSignYamlVerify(t *testing.T) {

	tmpDir := t.TempDir()

	// generate key pairs
	privKeyPath, pubKeyPath := generateKeypair(t, tmpDir)

	// Verify yaml must fail at first
	mustFail(signYamlVerify(pubKeyPath, testPayloadPath), t)

	// Now sign the yaml file; this must pass
	mustPass(signYaml(privKeyPath, testPayloadPath), t)

	// Verify yaml, this must pass
	mustPass(signYamlVerify(pubKeyPath, testSignedPayloadPath), t)

	cleanUp(testSignedPayloadPath)
}

func generateKeypair(t *testing.T, tmpDir string) (string, string) {

	keys, err := cosign.GenerateKeyPair(passFunc)
	if err != nil {
		t.Fatal(err)
	}

	privKeyPath := filepath.Join(tmpDir, "cosign.key")
	err = ioutil.WriteFile(privKeyPath, keys.PrivateBytes, 0600)
	if err != nil {
		t.Fatal(err)
	}
	pubKeyPath := filepath.Join(tmpDir, "cosign.pub")
	if err = ioutil.WriteFile(pubKeyPath, keys.PublicBytes, 0600); err != nil {
		t.Fatal(err)
	}

	return privKeyPath, pubKeyPath
}

func mustFail(err error, t *testing.T) {
	t.Helper()
	if err == nil {
		t.Fatal(err)
	}
}

func mustPass(err error, t *testing.T) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func cleanUp(path string) error {
	err := os.Remove(path)

	if err != nil {
		return errors.Wrap(err, "failed to remove  signed file")
	}
	return nil
}
