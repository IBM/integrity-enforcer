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
	"fmt"
	"strings"

	"github.com/ghodss/yaml"

	rsig "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/resourcesignature/v1alpha1"
	rsigcli "github.com/IBM/integrity-enforcer/enforcer/pkg/client/resourcesignature/clientset/versioned/typed/resourcesignature/v1alpha1"
	config "github.com/IBM/integrity-enforcer/enforcer/pkg/config"
	common "github.com/IBM/integrity-enforcer/enforcer/pkg/control/common"
	kubeutil "github.com/IBM/integrity-enforcer/enforcer/pkg/kubeutil"
	logger "github.com/IBM/integrity-enforcer/enforcer/pkg/logger"
	mapnode "github.com/IBM/integrity-enforcer/enforcer/pkg/mapnode"
	sign "github.com/IBM/integrity-enforcer/enforcer/pkg/sign"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type SignatureType string

const (
	SignatureTypeUnknown  SignatureType = ""
	SignatureTypeResource SignatureType = "Resource"
	SignatureTypeHelm     SignatureType = "Helm"
)

type SignStore interface {
	GetResourceSignature(ref *common.ResourceRef, reqc *common.ReqContext) *ResourceSignature
}

/**********************************************

				SignStore (singleton)

***********************************************/

var signStoreInstance SignStore

func GetSignStore() SignStore {
	if signStoreInstance == nil {
		signStoreInstance = &ConcreteSignStore{}
	}
	return signStoreInstance
}

type ConcreteSignStore struct {
	config        *config.SignStoreConfig
	helmSignStore *HelmSignStore
}

func InitSignStore(config *config.SignStoreConfig) {
	signStoreInstance = &ConcreteSignStore{
		config:        config,
		helmSignStore: NewHelmSignStore(config),
	}
}

func (self *ConcreteSignStore) GetResourceSignature(ref *common.ResourceRef, reqc *common.ReqContext) *ResourceSignature {

	sigAnnotations := reqc.ClaimedMetadata.Annotations.SignatureAnnotations()

	//1. pick ResourceSignature from metadata.annotation if available
	if sigAnnotations.Signature != "" {
		messageScope := sigAnnotations.MessageScope
		ignoreAttrs := sigAnnotations.IgnoreAttrs
		message := GenerateMessageFromRawObj(reqc.RawObject, messageScope, ignoreAttrs)
		signature := base64decode(sigAnnotations.Signature)
		return &ResourceSignature{
			SignType:    SignatureTypeResource,
			keyringPath: self.config.KeyringPath,
			data:        map[string]string{"signature": signature, "message": message, "matchMethod": ""},
			option:      map[string]bool{"matchRequired": false},
		}
	}

	//2. pick ResourceSignature from custom resource if available
	rsCR, err := findSignatureFromCR(self.config.SignatureNamespace)
	if err != nil {
		return nil
	}
	if rsCR != nil && len(rsCR.Items) > 0 {
		si, _, found := rsCR.FindSignItem(ref.ApiVersion, ref.Kind, ref.Name, ref.Namespace)
		if found {
			signature := base64decode(si.Signature)
			message := base64decode(si.Message)
			return &ResourceSignature{
				SignType:    SignatureTypeResource,
				keyringPath: self.config.KeyringPath,
				data:        map[string]string{"signature": signature, "message": message, "matchMethod": si.MatchMethod},
				option:      map[string]bool{"matchRequired": true},
			}
		}
	}

	//3. pick ResourceSignature from external store if available

	//4. helm resource (release secret, helm cahrt resources)
	return self.helmSignStore.GetResourceSignature(ref, reqc)

	//5. return nil if no signature found
	// return nil
}

type ResourceSignature struct {
	SignType    SignatureType
	keyringPath string
	data        map[string]string
	option      map[string]bool
}

type VerifierInterface interface {
	Verify(sig *ResourceSignature, reqc *common.ReqContext) (*SigVerifyResult, error)
}

type ResourceVerifier struct {
	Namespace string
}

func NewVerifier(signType SignatureType, enforcerNamespace string) VerifierInterface {
	if signType == SignatureTypeResource {
		return &ResourceVerifier{Namespace: enforcerNamespace}
	} else if signType == SignatureTypeHelm {
		return &HelmVerifier{Namespace: enforcerNamespace}
	}
	return nil
}

func (self *ResourceVerifier) Verify(sig *ResourceSignature, reqc *common.ReqContext) (*SigVerifyResult, error) {
	var vcerr *common.CheckError
	var vsinfo *common.SignerInfo
	var retErr error

	if sig.option["matchRequired"] {
		matched := self.MatchMessage(sig, reqc.RawObject, reqc.Kind, self.Namespace)
		if !matched {
			return &SigVerifyResult{
				Error: &common.CheckError{
					Msg:    "Message in ResourceSignature is not identical with the requested object",
					Reason: "Message in ResourceSignature is not identical with the requested object",
					Error:  nil,
				},
				Signer: nil,
			}, nil
		}
	}

	sigOk, reasonFail, signer, err := sign.VerifySignature(sig.keyringPath, sig.data["message"], sig.data["signature"])
	if err != nil {
		vcerr = &common.CheckError{
			Msg:    "Error occured in signature verification",
			Reason: reasonFail,
			Error:  err,
		}
		vsinfo = nil
		retErr = err
	} else if sigOk {
		vcerr = nil
		vsinfo = &common.SignerInfo{
			Email:   signer.Email,
			Name:    signer.Name,
			Comment: signer.Comment,
		}
		retErr = nil
	} else {
		vcerr = &common.CheckError{
			Msg:    "Failed to verify signature",
			Reason: reasonFail,
			Error:  nil,
		}
		vsinfo = nil
		retErr = nil
	}

	svresult := &SigVerifyResult{
		Error:  vcerr,
		Signer: vsinfo,
	}
	return svresult, retErr
}

func (self *ResourceVerifier) MatchMessage(sig *ResourceSignature, reqObj []byte, kind, enforcerNamespace string) bool {
	var mask []string
	matchMethod, _ := sig.data["matchMethod"]
	if matchMethod == rsig.MatchByExactMatch {
		mask = getMaskDef("")
	} else if matchMethod == rsig.MatchByKnownFilter {
		mask = getMaskDef(kind)
	}
	orgObj := []byte(sig.data["message"])
	matched := matchContents(orgObj, reqObj, mask)
	if !matched {
		orgNode, err := mapnode.NewFromYamlBytes(orgObj)
		if err != nil {
			logger.Error(fmt.Sprintf("Error in loading orgNode: %s", err.Error()))
			return false
		}
		nsMaskedOrgBytes := orgNode.Mask([]string{"metadata.namespace"}).ToYaml()
		simObj, err := kubeutil.DryRunCreate([]byte(nsMaskedOrgBytes), enforcerNamespace)
		if err != nil {
			logger.Error(fmt.Sprintf("Error in DryRunCreate: %s", err.Error()))
			return false
		}
		mask = getMaskDef("")
		mask = append(mask, "metadata.name") // DryRunCreate() uses name like `<name>-dry-run` to avoid already exists error
		matched = matchContents(simObj, reqObj, mask)
	}
	return matched
}

func getMaskDef(kind string) []string {
	maskDefBytes := []byte(`
		{
		}
	`)
	var maskDef map[string][]string
	err := json.Unmarshal(maskDefBytes, &maskDef)
	if err != nil {
		logger.Error(err)
		return []string{}
	}
	maskDef["*"] = common.CommonMessageMask

	masks := []string{}
	masks = append(masks, maskDef["*"]...)
	maskForKind, ok := maskDef[kind]
	if !ok {
		return masks
	}
	masks = append(masks, maskForKind...)
	return masks
}

func matchContents(orgObj, reqObj []byte, mask []string) bool {
	var orgMap map[string]interface{}
	err := yaml.Unmarshal(orgObj, &orgMap)
	if err != nil {
		logger.Error("Input original message is not in yaml format", string(orgObj))
		return false
	}
	orgNode, err := mapnode.NewFromMap(orgMap)
	if err != nil {
		logger.Error("Failed to load original message as *Node", string(orgObj))
		return false
	}
	reqNode, err := mapnode.NewFromBytes(reqObj)
	if err != nil {
		logger.Error("Failed to load requested object as *Node", string(reqObj))
		return false
	}

	matched := false
	maskedOrgNode := orgNode.Mask(mask)
	maskedReqNode := reqNode.Mask(mask)
	dr := maskedOrgNode.Diff(maskedReqNode)
	if dr == nil {
		matched = true
	} else {
		logger.Debug(dr.ToJson())
	}

	return matched
}

func findSignatureFromCR(namespace string) (*rsig.ResourceSignatureList, error) {
	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		return nil, err
	}
	rsigClient, err := rsigcli.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	rsiglObj, err := rsigClient.ResourceSignatures(namespace).List(metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	if len(rsiglObj.Items) == 0 {
		return nil, nil
	}
	return rsiglObj, nil
}

func GenerateMessageFromRawObj(rawObj []byte, filter, ignoreAttrs string) string {
	message := ""
	node, err := mapnode.NewFromBytes(rawObj)
	if err != nil {
		return ""
	}
	if ignoreAttrs != "" {
		ignoreAttrs = strings.ReplaceAll(ignoreAttrs, "\n", "")
		mask := strings.Split(ignoreAttrs, ",")
		for i := range mask {
			mask[i] = strings.Trim(mask[i], " ")
		}
		node = node.Mask(mask)
	}
	if filter == "" {
		message = node.ToJson() + "\n"
	} else {
		filter = strings.ReplaceAll(filter, "\n", "")
		filterKeys := strings.Split(filter, ",")
		for i := range filterKeys {
			filterKeys[i] = strings.Trim(filterKeys[i], " ")
		}
		for _, k := range filterKeys {
			subNodeList := node.MultipleSubNode(k)
			for _, subNode := range subNodeList {
				message += subNode.ToJson() + "\n"
			}
		}
	}
	return message
}

func base64decode(str string) string {
	decBytes, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return ""
	}
	dec := string(decBytes)
	return dec
}

type SigVerifyResult struct {
	Error  *common.CheckError
	Signer *common.SignerInfo
}
