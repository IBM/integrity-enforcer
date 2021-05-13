package yamlsign

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"path/filepath"

	gyaml "github.com/ghodss/yaml"
	"gopkg.in/yaml.v2"

	"github.com/sigstore/cosign/pkg/cosign"
)

func FetchYamlSignatures(ctx context.Context, payloadPath string) ([]cosign.SignedPayload, error) {

	var payload []byte
	var err error
	signatures := make([]cosign.SignedPayload, 1)
	if payloadPath != "" {

		payload, err = ioutil.ReadFile(filepath.Clean(payloadPath))
		m := make(map[interface{}]interface{})

		err = yaml.Unmarshal([]byte(payload), &m)
		if err != nil {
			fmt.Println("error: %v", err)
		}

		mMeta, ok := m["metadata"]
		if !ok {
			return nil, fmt.Errorf("there is no `metadata` in this payload")
		}
		mMetaMap, ok := mMeta.(map[interface{}]interface{})
		if !ok {
			return nil, fmt.Errorf("`metadata` in this payload is not a yaml object")
		}
		mAnnotation, ok := mMetaMap["annotations"]
		if !ok {
			return nil, fmt.Errorf("there is no `metadata.annotations` in this payload")
		}
		mAnnotationMap, ok := mAnnotation.(map[interface{}]interface{})
		if !ok {
			return nil, fmt.Errorf("`metadata.annotations` in this payload is not a yaml object")
		}

		msgAnnoKey := IntegrityShieldAnnotationMessage
		sigAnnoKey := IntegrityShieldAnnotationSignature
		certAnnoKey := IntegrityShieldAnnotationCertificate

		decodedMsg, _ := base64.StdEncoding.DecodeString(mAnnotationMap[msgAnnoKey].(string))
		payloadOrig, _ := gyaml.YAMLToJSON(decodedMsg)
		base64sig := fmt.Sprint(mAnnotationMap[sigAnnoKey])

		sp := cosign.SignedPayload{
			Payload:         payloadOrig,
			Base64Signature: base64sig,
		}

		encoded := mAnnotationMap[certAnnoKey].(string)

		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			fmt.Println("decode error:", err)
			return nil, err
		}
		decoded = gzipDecompress(decoded)

		certPem := string(decoded)

		if certPem != "" {
			certs, err := cosign.LoadCerts(certPem)
			if err != nil {
				return nil, err
			}
			sp.Cert = certs[0]
		}

		signatures[0] = sp
	}

	return signatures, nil
}

func gzipDecompress(in []byte) []byte {
	buffer := bytes.NewBuffer(in)
	reader, err := gzip.NewReader(buffer)
	if err != nil {
		return in
	}
	output := bytes.Buffer{}
	output.ReadFrom(reader)
	return output.Bytes()
}
