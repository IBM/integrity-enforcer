package yamlsign

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"

	gyaml "github.com/ghodss/yaml"
	"gopkg.in/yaml.v2"

	"github.com/sigstore/cosign/pkg/cosign"
)

const IntegrityShieldAnnotationMessage = "integrityshield.io/message"
const IntegrityShieldAnnotationSignature = "integrityshield.io/signature"
const IntegrityShieldAnnotationCertificate = "integrityshield.io/certificate"
const IntegrityShieldAnnotationBundle = "integrityshield.io/bundle"

func FetchYamlSignatures(ctx context.Context, payloadPath string) ([]cosign.SignedPayload, error) {

	signatures := make([]cosign.SignedPayload, 1)

	if payloadPath != "" {

		mPayload, _ := readPayload(payloadPath)

		mPayloadAnnotationMap, _ := getAnnotationMap(mPayload)

		msgAnnoKey := IntegrityShieldAnnotationMessage
		sigAnnoKey := IntegrityShieldAnnotationSignature
		certAnnoKey := IntegrityShieldAnnotationCertificate
		bundAnnoKey := IntegrityShieldAnnotationBundle

		var decodedMsg []byte
		encodedMsgIf := mPayloadAnnotationMap[msgAnnoKey]
		if encodedMsgIf != nil {
			encodedMsg := encodedMsgIf.(string)
			decodedMsg, _ = base64.StdEncoding.DecodeString(encodedMsg)
		}

		payloadOrig, _ := gyaml.YAMLToJSON(decodedMsg)
		base64sig := fmt.Sprint(mPayloadAnnotationMap[sigAnnoKey])

		var decodedBundle []byte
		encodedBundleIf := mPayloadAnnotationMap[bundAnnoKey]
		if encodedBundleIf != nil {
			encodedBundle := encodedBundleIf.(string)
			decodedBundle, _ = base64.StdEncoding.DecodeString(encodedBundle)
		}
		decodedBundle = gzipDecompress(decodedBundle)

		var bundle *cosign.Bundle
		if decodedBundle != nil {
			err := json.Unmarshal(decodedBundle, &bundle)
			if err != nil {
				fmt.Println("decode error:", err)
				return nil, err
			}
		}

		sp := cosign.SignedPayload{
			Payload:         payloadOrig,
			Base64Signature: base64sig,
		}
		if bundle != nil {
			sp.Bundle = bundle
		}

		var decodedCert []byte
		encodedCertIf := mPayloadAnnotationMap[certAnnoKey]
		if encodedCertIf != nil {
			encodedCert := encodedCertIf.(string)
			decodedCert, _ = base64.StdEncoding.DecodeString(encodedCert)
		}
		decodedCert = gzipDecompress(decodedCert)

		certPem := string(decodedCert)

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

func WriteYamlContent(signature []byte, pemBytes []byte, bundleJson []byte, mPayload map[interface{}]interface{}, payloadPath string) error {

	cleanPayloadYaml, err := yaml.Marshal(mPayload)

	if err != nil {
		return fmt.Errorf("error: %v", err)

	}

	mPayloadAnnotationMap, _ := getAnnotationMap(mPayload)

	msgAnnoKey := IntegrityShieldAnnotationMessage
	sigAnnoKey := IntegrityShieldAnnotationSignature
	certAnnoKey := IntegrityShieldAnnotationCertificate
	bundAnnoKey := IntegrityShieldAnnotationBundle

	mPayloadAnnotationMap[sigAnnoKey] = base64.StdEncoding.EncodeToString(signature)
	mPayloadAnnotationMap[msgAnnoKey] = base64.StdEncoding.EncodeToString(cleanPayloadYaml)
	compressed, _ := gzipCompress(bundleJson)
	mPayloadAnnotationMap[bundAnnoKey] = base64.StdEncoding.EncodeToString(compressed)

	if pemBytes != nil {
		mPayloadAnnotationMap[certAnnoKey] = base64.StdEncoding.EncodeToString(pemBytes)
	}

	mPayload["metadata"].(map[interface{}]interface{})["annotations"] = mPayloadAnnotationMap

	mapBytes, err := yaml.Marshal(mPayload)

	err = ioutil.WriteFile(filepath.Clean(payloadPath+".signed"), mapBytes, 0644)

	out := make(map[interface{}]interface{})

	signed, _ := ioutil.ReadFile(filepath.Clean(payloadPath + ".signed"))

	err = yaml.Unmarshal(signed, &out)
	if err != nil {
		panic(err)
	}
	return err
}

func FetchYamlContent(payloadPath string) (map[interface{}]interface{}, error) {

	mPayload, _ := readPayload(payloadPath)

	mPayloadAnnotationMap, _ := getAnnotationMap(mPayload)

	msgAnnoKey := IntegrityShieldAnnotationMessage
	sigAnnoKey := IntegrityShieldAnnotationSignature
	certAnnoKey := IntegrityShieldAnnotationCertificate
	bundAnnoKey := IntegrityShieldAnnotationBundle

	delete(mPayloadAnnotationMap, msgAnnoKey)
	delete(mPayloadAnnotationMap, sigAnnoKey)
	delete(mPayloadAnnotationMap, certAnnoKey)
	delete(mPayloadAnnotationMap, bundAnnoKey)

	if len(mPayloadAnnotationMap) == 0 {
		delete(mPayload["metadata"].(map[interface{}]interface{}), "annotations")
	} else {
		mPayload["metadata"].(map[interface{}]interface{})["annotations"] = mPayloadAnnotationMap
	}

	return mPayload, nil

}

func gzipCompress(in []byte) (compressedData []byte, err error) {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	_, err = gz.Write(in)
	if err != nil {
		return
	}
	if err = gz.Flush(); err != nil {
		return
	}
	if err = gz.Close(); err != nil {
		return
	}
	compressedData = b.Bytes()
	return
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

func readPayload(payloadPath string) (map[interface{}]interface{}, error) {
	var payloadYaml []byte

	payloadYaml, err := ioutil.ReadFile(filepath.Clean(payloadPath))

	mPayload := make(map[interface{}]interface{})

	err = yaml.Unmarshal([]byte(payloadYaml), &mPayload)
	if err != nil {
		fmt.Errorf("error: %v", err)
		return nil, err
	}
	return mPayload, nil
}

func getAnnotationMap(mPayload map[interface{}]interface{}) (map[interface{}]interface{}, error) {

	mPayloadMeta, ok := mPayload["metadata"]

	if !ok {
		return nil, fmt.Errorf("there is no `metadata` in this payload")
	}

	mPayloadMetaMap, ok := mPayloadMeta.(map[interface{}]interface{})
	if !ok {
		return nil, fmt.Errorf("`metadata` in this payload is not a yaml object")
	}

	mPayloadAnnotation, ok := mPayloadMetaMap["annotations"]
	if !ok {
		mPayloadAnnotation = make(map[interface{}]interface{})
	}

	mPayloadAnnotationMap, ok := mPayloadAnnotation.(map[interface{}]interface{})
	if !ok {
		return nil, fmt.Errorf("`metadata.annotations` in this payload is not a yaml object")
	}

	return mPayloadAnnotationMap, nil
}
