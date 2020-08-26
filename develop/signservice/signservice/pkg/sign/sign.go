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

package sign

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/IBM/integrity-enforcer/develop/signservice/signservice/pkg/pkix"

	rsig "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/resourcesignature/v1alpha1"
	iectlsign "github.com/IBM/integrity-enforcer/enforcer/pkg/control/sign"
	mapnode "github.com/IBM/integrity-enforcer/enforcer/pkg/mapnode"
	iesign "github.com/IBM/integrity-enforcer/enforcer/pkg/sign"
	"github.com/ghodss/yaml"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type SignMode string

const (
	DefaultSign SignMode = ""
	ApplySign   SignMode = "apply"
	PatchSign   SignMode = "patch"
)

const publicKeyPath = "/keyring/pubring.gpg"
const privateKeyPath = "/private-keyring/secring.gpg"

var useKnownFilterKinds = map[string]bool{
	"Deployment": true,
}

type User struct {
	Signer *iesign.Signer `json:"signer,omitempty"`
	Valid  bool           `json:"valid"`
}

func SignYaml(yamlBytes, scopeKeys, signer string, mode SignMode) (string, error) {

	jsonBytes, err := yaml.YAMLToJSON([]byte(yamlBytes))
	if err != nil {
		return "", errors.New(fmt.Sprintf("Error in loading yaml to json; %s", err.Error()))
	}
	msg := ""
	if scopeKeys == "" {
		msg = yamlBytes
	} else {
		msg = iectlsign.GenerateMessageFromRawObj(jsonBytes, scopeKeys, "")
	}

	sig, certPemBytes, err := pkix.GenerateSignature([]byte(msg), signer)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Error in signing yaml; %s", err.Error()))
	}
	if sig == nil {
		return "", errors.New("generated signature is null")
	}
	msgB64 := base64.StdEncoding.EncodeToString([]byte(msg))
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	certB64 := base64.StdEncoding.EncodeToString(certPemBytes)

	node, err := mapnode.NewFromBytes(jsonBytes)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Error in loading yaml to mapnode; %s", err.Error()))
	}

	sigNodeStr := ""
	if scopeKeys == "" {
		sigNodeStr = fmt.Sprintf("{\"metadata\":{\"annotations\":{\"message\":\"%s\",\"signature\":\"%s\",\"certificate\":\"%s\"}}}", msgB64, sigB64, certB64)
	} else {
		sigNodeStr = fmt.Sprintf("{\"metadata\":{\"annotations\":{\"messageScope\":\"%s\",\"signature\":\"%s\",\"certificate\":\"%s\"}}}", scopeKeys, sigB64, certB64)
	}
	sigNodeBytes := []byte(sigNodeStr)
	sigNode, err := mapnode.NewFromBytes(sigNodeBytes)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Error in loading signature to mapnode; %s", err.Error()))
	}

	mergedNode, err := node.Merge(sigNode)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Error in mergine yaml and signature; %s", err.Error()))
	}
	signedYaml := mergedNode.ToYaml()

	return signedYaml, nil
}

func CreateResourceSignature(yamlBytes, signer, namespaceInQuery, scope string, mode SignMode) (string, error) {

	jsonBytes, err := yaml.YAMLToJSON([]byte(yamlBytes))
	if err != nil {
		return "", errors.New(fmt.Sprintf("Error in loading yaml to json; %s", err.Error()))
	}
	node, err := mapnode.NewFromBytes(jsonBytes)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Error in loading yaml to mapnode; %s", err.Error()))
	}
	apiVersion := node.GetString("apiVersion")
	kind := node.GetString("kind")
	name := node.GetString("metadata.name")
	mutableAttrs := node.GetString("metadata.annotations.mutableAttrs")
	namespaceInYaml := node.GetString("metadata.namespace")
	namespace := namespaceInQuery
	if namespace == "" {
		namespace = namespaceInYaml
	}
	if apiVersion == "" || kind == "" || name == "" || namespace == "" {
		return "", errors.New(fmt.Sprintf("required value is empty; apiVersion: %s, kind: %s, metadata.name: %s, metadata.namespace: %s", apiVersion, kind, name, namespace))
	}

	signType := rsig.SignatureTypeResource

	if mode == ApplySign {
		signType = rsig.SignatureTypeApplyingResource
	} else if mode == PatchSign {
		signType = rsig.SignatureTypePatch
	}

	var signItem rsig.SignItem
	if scope == "" {
		msgB64 := base64.StdEncoding.EncodeToString([]byte(yamlBytes))

		sig, certPemBytes, err := pkix.GenerateSignature([]byte(yamlBytes), signer)
		if err != nil {
			return "", errors.New(fmt.Sprintf("Error in signing yaml; %s", err.Error()))
		}
		if sig == nil {
			return "", errors.New("generated signature is null")
		}
		sigB64 := base64.StdEncoding.EncodeToString(sig)
		certB64 := base64.StdEncoding.EncodeToString(certPemBytes)

		signItem = rsig.SignItem{
			ApiVersion: apiVersion,
			Kind:       kind,
			Metadata: rsig.SignItemMeta{
				Name:      name,
				Namespace: namespace,
			},
			Message:      msgB64,
			MutableAttrs: mutableAttrs,
			Signature:    sigB64,
			Certificate:  certB64,
			Type:         signType,
		}
	} else {
		scopeKeys := mapnode.SplitCommaSeparatedKeys(scope)
		message := ""
		for _, k := range scopeKeys {
			subNodeList := node.MultipleSubNode(k)
			for _, subNode := range subNodeList {
				message += subNode.ToJson() + "\n"
			}
		}
		sig, certBytes, err := pkix.GenerateSignature([]byte(message), signer)
		if err != nil {
			return "", errors.New(fmt.Sprintf("Error in signing yaml; %s", err.Error()))
		}
		if sig == nil {
			return "", errors.New("generated signature is null")
		}
		sigB64 := base64.StdEncoding.EncodeToString(sig)
		certB64 := base64.StdEncoding.EncodeToString(certBytes)
		signItem = rsig.SignItem{
			ApiVersion: apiVersion,
			Kind:       kind,
			Metadata: rsig.SignItemMeta{
				Name:      name,
				Namespace: namespace,
			},
			MessageScope: scope,
			MutableAttrs: mutableAttrs,
			Signature:    sigB64,
			Certificate:  certB64,
			Type:         signType,
		}

	}

	rsName := fmt.Sprintf("rsig-%s-%s-%s", namespace, strings.ToLower(kind), name)
	rs := rsig.ResourceSignature{
		ObjectMeta: metav1.ObjectMeta{
			Name: rsName,
		},
		Spec: rsig.ResourceSignatureSpec{
			Data: []rsig.SignItem{
				signItem,
			},
		},
	}
	rsigBytes, err := yaml.Marshal(rs)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Error in dumping ResourceSignature yaml; %s", err.Error()))
	}
	rsigNode, err := mapnode.NewFromYamlBytes(rsigBytes)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Error in loading ResourceSignature to mapnode; %s", err.Error()))
	}
	rsigApiVersion := rsig.SchemeGroupVersion.String()
	rsigKind := "ResourceSignature"
	rsigMetaNodeStr := fmt.Sprintf("{\"apiVersion\":\"%s\",\"kind\":\"%s\"}", rsigApiVersion, rsigKind)
	rsigMetaNodeBytes := []byte(rsigMetaNodeStr)
	rsigMetaNode, err := mapnode.NewFromBytes(rsigMetaNodeBytes)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Error in loading metadata for ResourceSignature to mapnode; %s", err.Error()))
	}
	mergedRsigNode, err := rsigNode.Merge(rsigMetaNode)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Error in merging ResourceSignature and metadata; %s", err.Error()))
	}
	mergedRsigNode = mergedRsigNode.Mask([]string{"status", "metadata.creationTimestamp"})
	mergedRsigStr := mergedRsigNode.ToYaml()

	return mergedRsigStr, nil
}

func SignBytes(msg []byte, signer string) ([]byte, error) {
	sig, certPemBytes, err := pkix.GenerateSignature([]byte(msg), signer)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error in signing bytes; %s", err.Error()))
	}
	msgB64 := base64.StdEncoding.EncodeToString(msg)
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	certB64 := base64.StdEncoding.EncodeToString(certPemBytes)
	result := map[string]string{}
	result["message"] = msgB64
	result["signature"] = sigB64
	result["certificate"] = certB64
	resultBytes, err := json.Marshal(result)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error in marshaling sig/cert to bytes; %s", err.Error()))
	}
	return resultBytes, nil
}

func ListUsers(mode string) (string, error) {
	pubkeyList, err := iesign.LoadKeyRing(publicKeyPath)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Error in loading public keyring; %s", err.Error()))
	}
	seckeyList, err := iesign.LoadKeyRing(privateKeyPath)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Error in loading private keyring; %s", err.Error()))
	}

	pubSigners := iesign.GetSignersFromEntityList(pubkeyList)
	secSigners := iesign.GetSignersFromEntityList(seckeyList)

	users := []*User{}
	for _, signer := range secSigners {
		user := &User{
			Signer: signer,
			Valid:  false,
		}
		for _, pubSigner := range pubSigners {
			if pubSigner.EqualTo(signer) {
				user.Valid = true
				break
			}
		}
		doAppend := (mode == "all") || (mode == "valid" && user.Valid) || (mode == "invalid" && !user.Valid)
		if doAppend {
			users = append(users, user)
		}

	}
	usersBytes, err := json.Marshal(users)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Error in marshaling users; %s", err.Error()))
	}
	return string(usersBytes), nil
}

func ListCerts(mode string) (string, error) {
	return pkix.ListCerts()
}
