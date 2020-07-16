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
	pkix "github.com/IBM/integrity-enforcer/enforcer/pkg/sign/pkix"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type SignatureType string

const (
	SignatureTypeUnknown          SignatureType = ""
	SignatureTypeResource         SignatureType = "Resource"
	SignatureTypeApplyingResource SignatureType = "ApplyingResource"
	SignatureTypePatch            SignatureType = "Patch"
	SignatureTypeHelm             SignatureType = "Helm"
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
		message := base64decode(sigAnnotations.Message)
		messageScope := sigAnnotations.MessageScope
		ignoreAttrs := sigAnnotations.IgnoreAttrs
		matchRequired := true
		scopedSignature := false
		if message == "" && messageScope != "" {
			message = GenerateMessageFromRawObj(reqc.RawObject, messageScope, ignoreAttrs)
			matchRequired = false  // skip matching because the message is generated from Requested Object
			scopedSignature = true // enable checking if the signature is for patch
		}
		signature := base64decode(sigAnnotations.Signature)
		certificate := base64decode(sigAnnotations.Certificate)
		signType := SignatureTypeResource
		if sigAnnotations.SignatureType == rsig.SignatureTypeApplyingResource {
			signType = SignatureTypeApplyingResource
		} else if sigAnnotations.SignatureType == rsig.SignatureTypePatch {
			signType = SignatureTypePatch
		}
		return &ResourceSignature{
			SignType:     signType,
			certPoolPath: self.config.CertPoolPath,
			data:         map[string]string{"signature": signature, "message": message, "certificate": certificate, "scope": messageScope},
			option:       map[string]bool{"matchRequired": matchRequired, "scopedSignature": scopedSignature},
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
			certificate := base64decode(si.Certificate)
			message := base64decode(si.Message)
			matchRequired := true
			scopedSignature := false
			if si.Message == "" && si.MessageScope != "" {
				message = GenerateMessageFromRawObj(reqc.RawObject, si.MessageScope, "")
				matchRequired = false  // skip matching because the message is generated from Requested Object
				scopedSignature = true // enable checking if the signature is for patch
			}
			signType := SignatureTypeResource
			if si.Type == rsig.SignatureTypeApplyingResource {
				signType = SignatureTypeApplyingResource
			} else if si.Type == rsig.SignatureTypePatch {
				signType = SignatureTypePatch
			}
			return &ResourceSignature{
				SignType:     signType,
				certPoolPath: self.config.CertPoolPath,
				data:         map[string]string{"signature": signature, "message": message, "certificate": certificate, "scope": si.MessageScope},
				option:       map[string]bool{"matchRequired": matchRequired, "scopedSignature": scopedSignature},
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
	SignType     SignatureType
	certPoolPath string
	keyringPath  string // TODO: remove this after support cert verification for helm case
	data         map[string]string
	option       map[string]bool
}

type VerifierInterface interface {
	Verify(sig *ResourceSignature, reqc *common.ReqContext) (*SigVerifyResult, error)
}

type ResourceVerifier struct {
	Namespace string
}

func NewVerifier(signType SignatureType, enforcerNamespace string) VerifierInterface {
	if signType == SignatureTypeResource || signType == SignatureTypeApplyingResource || signType == SignatureTypePatch {
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
		message, _ := sig.data["message"]
		matched := self.MatchMessage([]byte(message), reqc.RawObject, self.Namespace, sig.SignType)
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

	if sig.option["scopedSignature"] {
		isValidScopeSignature := false
		scopeDenyMsg := ""
		if reqc.IsCreateRequest() {
			// for CREATE request, this boolean flag will be true.
			// because signature verification will work as value check in the case of scopedSignature.
			isValidScopeSignature = true
		} else if reqc.IsUpdateRequest() {
			// for UPDATE request, IE will confirm that no value is modified except attributes in `scope`.
			// if there is any modification, the request will be denied.
			if reqc.OrgMetadata.Annotations.IntegrityVerified() {
				scope, _ := sig.data["scope"]
				diffIsInMessageScope := self.IsPatchWithScopeKey(reqc.RawOldObject, reqc.RawObject, scope)
				if diffIsInMessageScope {
					isValidScopeSignature = true
				} else {
					scopeDenyMsg = "messageScope of the signature does not cover all changed attributes in this update"
				}
			} else {
				scopeDenyMsg = "Original object must be integrityVerified to allow UPDATE request with scope signature"
			}
		}
		if !isValidScopeSignature {
			return &SigVerifyResult{
				Error: &common.CheckError{
					Msg:    scopeDenyMsg,
					Reason: scopeDenyMsg,
					Error:  nil,
				},
				Signer: nil,
			}, nil
		}
	}

	certificate := []byte(sig.data["certificate"])
	certOk, reasonFail, err := pkix.VerifyCertificate(certificate, sig.certPoolPath)
	if err != nil {
		vcerr = &common.CheckError{
			Msg:    "Error occured in certificate verification",
			Reason: reasonFail,
			Error:  err,
		}
		vsinfo = nil
		retErr = err
	} else if !certOk {
		vcerr = &common.CheckError{
			Msg:    "Failed to verify certificate",
			Reason: reasonFail,
			Error:  nil,
		}
		vsinfo = nil
		retErr = nil
	} else {
		certDN, err := pkix.GetSubjectFromCertificate(certificate)
		if err != nil {
			logger.Error("Failed to get subject from certificate; ", err)
		}
		pubKeyBytes, err := pkix.GetPublicKeyFromCertificate(certificate)
		if err != nil {
			logger.Error("Failed to get public key from certificate; ", err)
		}
		message := []byte(sig.data["message"])
		signature := []byte(sig.data["signature"])
		sigOk, reasonFail, err := pkix.VerifySignature(message, signature, pubKeyBytes)
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
			vsinfo = common.NewSignerInfoFromPKIXName(certDN)
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
	}

	svresult := &SigVerifyResult{
		Error:  vcerr,
		Signer: vsinfo,
	}
	return svresult, retErr
}

func (self *ResourceVerifier) MatchMessage(message, reqObj []byte, enforcerNamespace string, signType SignatureType) bool {
	var mask []string
	mask = getMaskDef("")

	orgObj := []byte(message)
	matched := matchContents(orgObj, reqObj, mask)
	if matched {
		logger.Debug("matched directly")
	}
	if !matched && signType == SignatureTypeResource {
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
		mask = append(mask, "status")        // DryRunCreate() may generate different status. this will be ignored.
		matched = matchContents(simObj, reqObj, mask)
		if matched {
			logger.Debug("matched by DryRunCreate()")
		}
	}
	if !matched && signType == SignatureTypeApplyingResource {

		reqNode, _ := mapnode.NewFromBytes(reqObj)
		reqNamespace := reqNode.GetString("metadata.namespace")
		_, patchedBytes, err := kubeutil.GetApplyPatchBytes(orgObj, reqNamespace)
		if err != nil {
			logger.Error(fmt.Sprintf("Error in getting patched bytes: %s", err.Error()))
			return false
		}
		patchedNode, _ := mapnode.NewFromBytes(patchedBytes)
		nsMaskedPatchedNode := patchedNode.Mask([]string{"metadata.namespace"})
		simPatchedObj, err := kubeutil.DryRunCreate([]byte(nsMaskedPatchedNode.ToYaml()), enforcerNamespace)
		if err != nil {
			logger.Error(fmt.Sprintf("Error in DryRunCreate for Patch: %s", err.Error()))
			return false
		}
		mask = getMaskDef("")
		mask = append(mask, "metadata.name") // DryRunCreate() uses name like `<name>-dry-run` to avoid already exists error
		mask = append(mask, "status")        // DryRunCreate() may generate different status. this will be ignored.
		matched = matchContents(simPatchedObj, reqObj, mask)
		if matched {
			logger.Debug("matched by GetApplyPatchBytes()")
		}
	}
	if !matched && signType == SignatureTypePatch {
		patchedBytes, err := kubeutil.StrategicMergePatch(reqObj, orgObj, "")
		if err != nil {
			logger.Error(fmt.Sprintf("Error in getting patched bytes: %s", err.Error()))
			return false
		}
		patchedNode, _ := mapnode.NewFromBytes(patchedBytes)
		nsMaskedPatchedNode := patchedNode.Mask([]string{"metadata.namespace"})
		simPatchedObj, err := kubeutil.DryRunCreate([]byte(nsMaskedPatchedNode.ToYaml()), enforcerNamespace)
		if err != nil {
			logger.Error(fmt.Sprintf("Error in DryRunCreate for Patch: %s", err.Error()))
			return false
		}
		mask = getMaskDef("")
		mask = append(mask, "metadata.name") // DryRunCreate() uses name like `<name>-dry-run` to avoid already exists error
		mask = append(mask, "status")        // DryRunCreate() may generate different status. this will be ignored.
		matched = matchContents(simPatchedObj, reqObj, mask)
		if matched {
			logger.Debug("matched by StrategicMergePatch()")
		}
	}
	return matched
}

func (self *ResourceVerifier) IsPatchWithScopeKey(orgObj, rawObj []byte, scope string) bool {
	var mask []string
	mask = getMaskDef("")
	scopeKeys := mapnode.SplitCommaSeparatedKeys(scope)
	mask = append(mask, scopeKeys...)
	matched := matchContents(orgObj, rawObj, mask)
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
		filterKeys := mapnode.SplitCommaSeparatedKeys(filter)
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
