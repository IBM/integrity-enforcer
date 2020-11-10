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
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	hrm "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/helmreleasemetadata/v1alpha1"
	common "github.com/IBM/integrity-enforcer/enforcer/pkg/common/common"
	profile "github.com/IBM/integrity-enforcer/enforcer/pkg/common/profile"
	helm "github.com/IBM/integrity-enforcer/enforcer/pkg/plugins/helm"
	kubeutil "github.com/IBM/integrity-enforcer/enforcer/pkg/util/kubeutil"
	logger "github.com/IBM/integrity-enforcer/enforcer/pkg/util/logger"
	mapnode "github.com/IBM/integrity-enforcer/enforcer/pkg/util/mapnode"
	pgp "github.com/IBM/integrity-enforcer/enforcer/pkg/util/sign/pgp"
	x509 "github.com/IBM/integrity-enforcer/enforcer/pkg/util/sign/x509"
)

/**********************************************

				Verifier

***********************************************/

type VerifierInterface interface {
	Verify(sig *GeneralSignature, reqc *common.ReqContext, signingProfile profile.SigningProfile) (*SigVerifyResult, error)
}

/**********************************************

				ResourceVerifier

***********************************************/

type ResourceVerifier struct {
	VerifyType  VerifyType
	Namespace   string
	KeyPathList []string
}

func NewVerifier(verifyType VerifyType, signType SignatureType, enforcerNamespace string, keyPathList []string) VerifierInterface {
	if signType == SignatureTypeResource || signType == SignatureTypeApplyingResource || signType == SignatureTypePatch {
		return &ResourceVerifier{Namespace: enforcerNamespace, VerifyType: verifyType, KeyPathList: keyPathList}
	} else if signType == SignatureTypeHelm {
		return &HelmVerifier{Namespace: enforcerNamespace, VerifyType: verifyType, KeyPathList: keyPathList}
	}
	return nil
}

func (self *ResourceVerifier) Verify(sig *GeneralSignature, reqc *common.ReqContext, signingProfile profile.SigningProfile) (*SigVerifyResult, error) {
	var vcerr *common.CheckError
	var vsinfo *common.SignerInfo
	var retErr error

	kustomizeList := signingProfile.Kustomize(reqc.Map())
	allowDiffPatterns := makeAllowDiffPatterns(reqc, kustomizeList)

	protectAttrsList := signingProfile.ProtectAttrs(reqc.Map())
	unprotectAttrsList := signingProfile.UnprotectAttrs(reqc.Map())

	if sig.option["matchRequired"] {
		message, _ := sig.data["message"]
		// use yamlBytes if single yaml data is extracted from ResourceSignature
		if yamlBytes, ok := sig.data["yamlBytes"]; ok {
			message = yamlBytes
		}

		matched, diffStr := self.MatchMessage([]byte(message), reqc.RawObject, protectAttrsList, unprotectAttrsList, allowDiffPatterns, reqc.ResourceScope, sig.SignType)
		if !matched {
			msg := fmt.Sprintf("Message in ResourceSignature is not identical with the requested object. diff: %s", diffStr)
			return &SigVerifyResult{
				Error: &common.CheckError{
					Msg:    msg,
					Reason: msg,
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
			if reqc.OrgMetadata.Labels.IntegrityVerified() {
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

	if self.VerifyType == VerifyTypePGP {
		message := sig.data["message"]
		signature := sig.data["signature"]
		ok, reasonFail, signer, err := pgp.VerifySignature(self.KeyPathList, message, signature)
		if err != nil {
			vcerr = &common.CheckError{
				Msg:    "Error occured in signature verification",
				Reason: reasonFail,
				Error:  err,
			}
			vsinfo = nil
			retErr = err
		} else if ok {
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

	} else if self.VerifyType == VerifyTypeX509 {
		certificate := []byte(sig.data["certificate"])
		certOk, reasonFail, err := x509.VerifyCertificate(certificate, self.KeyPathList)
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
			cert, err := x509.ParseCertificate(certificate)
			if err != nil {
				logger.Error("Failed to parse certificate; ", err)
			}
			pubKeyBytes, err := x509.GetPublicKeyFromCertificate(certificate)
			if err != nil {
				logger.Error("Failed to get public key from certificate; ", err)
			}
			message := []byte(sig.data["message"])
			signature := []byte(sig.data["signature"])
			sigOk, reasonFail, err := x509.VerifySignature(message, signature, pubKeyBytes)
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
				vsinfo = x509.NewSignerInfoFromCert(cert)
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
	} else {
		errMsg := fmt.Sprintf("Unknown VerifyType is specified; VerifyType: %s", string(self.VerifyType))
		vcerr = &common.CheckError{
			Msg:    errMsg,
			Reason: errMsg,
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

func (self *ResourceVerifier) MatchMessage(message, reqObj []byte, protectAttrs, unprotectAttrs []*profile.AttrsPattern, allowDiffPatterns []*mapnode.Difference, resScope string, signType SignatureType) (bool, string) {
	var mask, focus []string
	matched := false
	diffStr := ""
	mask = getMaskDef("")

	orgObj := []byte(message)
	orgNode, err := mapnode.NewFromYamlBytes(orgObj)
	if err != nil {
		logger.Error(fmt.Sprintf("Error in loading orgNode: %s", err.Error()))
		return false, ""
	}

	focus = []string{}
	for _, attrs := range protectAttrs {
		focus = append(focus, attrs.Attrs...)
	}

	addMask := []string{}
	if len(focus) == 0 {
		for _, attrs := range unprotectAttrs {
			addMask = append(addMask, attrs.Attrs...)
		}
		mask = append(mask, addMask...)
	}

	matched, diffStr = matchContents(orgObj, reqObj, focus, mask, allowDiffPatterns)
	if matched {
		logger.Debug("matched directly")
	}

	// do not attempt to DryRun for Cluster scope resource
	// because ie-sa does not have role for creating "any" resource at cluster scope
	if resScope == "Cluster" {
		return matched, diffStr
	}

	if !matched && signType == SignatureTypeResource {

		nsMaskedOrgBytes := orgNode.Mask([]string{"metadata.namespace"}).ToYaml()
		simObj, err := kubeutil.DryRunCreate([]byte(nsMaskedOrgBytes), self.Namespace)
		if err != nil {
			logger.Error(fmt.Sprintf("Error in DryRunCreate: %s", err.Error()))
			return false, ""
		}
		mask = getMaskDef("")
		mask = append(mask, addMask...)
		mask = append(mask, "metadata.name") // DryRunCreate() uses name like `<name>-dry-run` to avoid already exists error
		mask = append(mask, "status")        // DryRunCreate() may generate different status. this will be ignored.

		matched, diffStr = matchContents(simObj, reqObj, focus, mask, allowDiffPatterns)
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
			return false, ""
		}
		patchedNode, _ := mapnode.NewFromBytes(patchedBytes)
		nsMaskedPatchedNode := patchedNode.Mask([]string{"metadata.namespace"})
		simPatchedObj, err := kubeutil.DryRunCreate([]byte(nsMaskedPatchedNode.ToYaml()), self.Namespace)
		if err != nil {
			logger.Error(fmt.Sprintf("Error in DryRunCreate for Patch: %s", err.Error()))
			return false, ""
		}
		mask = getMaskDef("")
		mask = append(mask, addMask...)
		mask = append(mask, "metadata.name") // DryRunCreate() uses name like `<name>-dry-run` to avoid already exists error
		mask = append(mask, "status")        // DryRunCreate() may generate different status. this will be ignored.
		matched, diffStr = matchContents(simPatchedObj, reqObj, focus, mask, allowDiffPatterns)
		if matched {
			logger.Debug("matched by GetApplyPatchBytes()")
		}
	}
	if !matched && signType == SignatureTypePatch {
		patchedBytes, err := kubeutil.StrategicMergePatch(reqObj, orgObj, "")
		if err != nil {
			logger.Error(fmt.Sprintf("Error in getting patched bytes: %s", err.Error()))
			return false, ""
		}
		patchedNode, _ := mapnode.NewFromBytes(patchedBytes)
		nsMaskedPatchedNode := patchedNode.Mask([]string{"metadata.namespace"})
		simPatchedObj, err := kubeutil.DryRunCreate([]byte(nsMaskedPatchedNode.ToYaml()), self.Namespace)
		if err != nil {
			logger.Error(fmt.Sprintf("Error in DryRunCreate for Patch: %s", err.Error()))
			return false, ""
		}
		mask = getMaskDef("")
		mask = append(mask, addMask...)
		mask = append(mask, "metadata.name") // DryRunCreate() uses name like `<name>-dry-run` to avoid already exists error
		mask = append(mask, "status")        // DryRunCreate() may generate different status. this will be ignored.
		matched, diffStr = matchContents(simPatchedObj, reqObj, focus, mask, allowDiffPatterns)
		if matched {
			logger.Debug("matched by StrategicMergePatch()")
		}
	}
	return matched, diffStr
}

func (self *ResourceVerifier) IsPatchWithScopeKey(orgObj, rawObj []byte, scope string) bool {
	var mask []string
	mask = getMaskDef("")
	scopeKeys := mapnode.SplitCommaSeparatedKeys(scope)
	mask = append(mask, scopeKeys...)
	matched, _ := matchContents(orgObj, rawObj, nil, mask, nil)
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
	maskDef["*"] = CommonMessageMask

	masks := []string{}
	masks = append(masks, maskDef["*"]...)
	maskForKind, ok := maskDef[kind]
	if !ok {
		return masks
	}
	masks = append(masks, maskForKind...)
	return masks
}

func matchContents(orgObj, reqObj []byte, focus, mask []string, allowDiffPatterns []*mapnode.Difference) (bool, string) {
	orgNode, err := mapnode.NewFromYamlBytes(orgObj)
	if err != nil {
		logger.Error("Failed to load original message as *Node", string(orgObj))
		return false, ""
	}
	reqNode, err := mapnode.NewFromBytes(reqObj)
	if err != nil {
		logger.Error("Failed to load requested object as *Node", string(reqObj))
		return false, ""
	}

	matched := false
	orgNodeToCompare := orgNode.Copy()
	reqNodeToCompare := reqNode.Copy()
	if len(focus) > 0 {
		orgNodeToCompare = orgNode.Extract(focus)
		reqNodeToCompare = reqNode.Extract(focus)
	} else {
		orgNodeToCompare = orgNode.Mask(mask)
		reqNodeToCompare = reqNode.Mask(mask)
	}

	dr := orgNodeToCompare.Diff(reqNodeToCompare)
	if dr != nil && len(allowDiffPatterns) > 0 {
		dr = dr.Remove(allowDiffPatterns)
	}
	diffStr := ""

	if dr == nil {
		matched = true
	}

	if !matched && dr != nil {
		diffStr = dr.String()
	}

	return matched, diffStr
}

func GenerateMessageFromRawObj(rawObj []byte, filter, mutableAttrs string) string {
	message := ""
	node, err := mapnode.NewFromBytes(rawObj)
	if err != nil {
		return ""
	}
	if mutableAttrs != "" {
		mutableAttrs = strings.ReplaceAll(mutableAttrs, "\n", "")
		mask := strings.Split(mutableAttrs, ",")
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

func decompress(str string) string {
	if str == "" {
		return str
	}
	buffer := strings.NewReader(str)
	reader, err := gzip.NewReader(buffer)
	if err != nil {
		return str
	}
	output := bytes.Buffer{}
	output.ReadFrom(reader)
	s := string(output.Bytes())
	return s
}

func makeAllowDiffPatterns(reqc *common.ReqContext, kustomizeList []*profile.KustomizePattern) []*mapnode.Difference {
	ref := reqc.ResourceRef()
	name := reqc.Name
	kustomizedName := name
	for _, pattern := range kustomizeList {
		newRef := pattern.OverrideName(ref)
		kustomizedName = newRef.Name
	}
	if kustomizedName == name {
		return nil
	}

	key := "metadata.name"
	values := map[string]interface{}{
		"before": name,
		"after":  kustomizedName,
	}
	allowDiffPattern := &mapnode.Difference{
		Key:    key,
		Values: values,
	}
	return []*mapnode.Difference{allowDiffPattern}
}

type SigVerifyResult struct {
	Error  *common.CheckError
	Signer *common.SignerInfo
}

/**********************************************

				HelmVerifier

***********************************************/

type HelmVerifier struct {
	VerifyType  VerifyType
	Namespace   string
	KeyPathList []string
}

func (self *HelmVerifier) Verify(sig *GeneralSignature, reqc *common.ReqContext, signingProfile profile.SigningProfile) (*SigVerifyResult, error) {
	var vcerr *common.CheckError
	var vsinfo *common.SignerInfo
	var retErr error

	rlsStr, _ := sig.data["releaseSecret"]
	hrmStr, _ := sig.data["helmReleaseMetadata"]

	if sig.option["matchRequired"] {
		matched := helm.MatchReleaseSecret(rlsStr, hrmStr)
		if !matched {
			return &SigVerifyResult{
				Error: &common.CheckError{
					Msg:    "HelmReleaseMetadata is not identical with the release secret",
					Reason: "HelmReleaseMetadata is not identical with the release secret",
					Error:  nil,
				},
				Signer: nil,
			}, nil
		}
	}

	// verify helm chart with prov in HelmReleaseMetadata.
	// helm provenance supports only PGP Verification.
	if self.VerifyType == VerifyTypePGP || self.VerifyType == VerifyTypeX509 {
		var hrmObj *hrm.HelmReleaseMetadata
		err := json.Unmarshal([]byte(hrmStr), &hrmObj)
		if err != nil {
			msg := fmt.Sprintf("Error occured in helm chart verification; %s", err.Error())
			vcerr = &common.CheckError{
				Msg:    msg,
				Reason: msg,
				Error:  fmt.Errorf("%s", msg),
			}
			vsinfo = nil
			retErr = err
		} else {

			helmChart := hrmObj.Spec.Chart
			helmProv := hrmObj.Spec.Prov
			ok, signer, reasonFail, err := helm.VerifyChartAndProv(helmChart, helmProv, self.KeyPathList)
			if err != nil {
				vcerr = &common.CheckError{
					Msg:    "Error occured in helm chart verification",
					Reason: reasonFail,
					Error:  err,
				}
				vsinfo = nil
				retErr = err
			} else if ok {
				vcerr = nil
				vsinfo = &common.SignerInfo{
					Email:   signer.Email,
					Name:    signer.Name,
					Comment: signer.Comment,
				}
				retErr = nil
			} else {
				vcerr = &common.CheckError{
					Msg:    "Failed to verify helm chart and its provenance",
					Reason: reasonFail,
					Error:  nil,
				}
				vsinfo = nil
				retErr = nil
			}
		}
	} else {
		errMsg := fmt.Sprintf("Unknown VerifyType is specified; VerifyType: %s", string(self.VerifyType))
		vcerr = &common.CheckError{
			Msg:    errMsg,
			Reason: errMsg,
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

var CommonMessageMask = []string{
	fmt.Sprintf("metadata.labels.\"%s\"", common.ResourceIntegrityLabelKey),
	fmt.Sprintf("metadata.labels.\"%s\"", common.ReasonLabelKey),
	"metadata.annotations.message",
	"metadata.annotations.signature",
	"metadata.annotations.certificate",
	"metadata.annotations.signPaths",
	"metadata.annotations.namespace",
	"metadata.annotations.kubectl.\"kubernetes.io/last-applied-configuration\"",
	"metadata.managedFields",
	"metadata.creationTimestamp",
	"metadata.generation",
	"metadata.annotations.deprecated.daemonset.template.generation",
	"metadata.namespace",
	"metadata.resourceVersion",
	"metadata.selfLink",
	"metadata.uid",
}
