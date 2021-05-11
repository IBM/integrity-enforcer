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

package shield

import (
	"encoding/json"
	"fmt"
	"strings"

	hrm "github.com/IBM/integrity-enforcer/shield/pkg/apis/helmreleasemetadata/v1alpha1"
	rspapi "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesigningprofile/v1alpha1"
	common "github.com/IBM/integrity-enforcer/shield/pkg/common"
	helm "github.com/IBM/integrity-enforcer/shield/pkg/plugins/helm"
	kubeutil "github.com/IBM/integrity-enforcer/shield/pkg/util/kubeutil"
	logger "github.com/IBM/integrity-enforcer/shield/pkg/util/logger"
	mapnode "github.com/IBM/integrity-enforcer/shield/pkg/util/mapnode"
	sign "github.com/IBM/integrity-enforcer/shield/pkg/util/sign"
	pgp "github.com/IBM/integrity-enforcer/shield/pkg/util/sign/pgp"
	sigstore "github.com/IBM/integrity-enforcer/shield/pkg/util/sign/sigstore"
	x509 "github.com/IBM/integrity-enforcer/shield/pkg/util/sign/x509"
)

/**********************************************

				Verifier

***********************************************/

type VerifierInterface interface {
	Verify(sig *GeneralSignature, v2resc *common.V2ResourceContext, signingProfile rspapi.ResourceSigningProfile) (*SigVerifyResult, []string, error)
}

/**********************************************

				ResourceVerifier

***********************************************/

type ResourceVerifier struct {
	PGPKeyPathList        []string
	X509CertPathList      []string
	SigStoreCertPathList  []string
	AllMountedKeyPathList []string
	dryRunNamespace       string // namespace for dryrun; should be empty for cluster scope request
	sigstoreEnabled       bool
}

func NewVerifier(signType SignedResourceType, dryRunNamespace string, pgpKeyPathList, x509CertPathList, sigStoreCertPathList, allKeyPathList []string, sigstoreEnabled bool) VerifierInterface {
	if signType == SignedResourceTypeResource || signType == SignedResourceTypeApplyingResource || signType == SignedResourceTypePatch {
		return &ResourceVerifier{dryRunNamespace: dryRunNamespace, PGPKeyPathList: pgpKeyPathList, X509CertPathList: x509CertPathList, SigStoreCertPathList: sigStoreCertPathList, AllMountedKeyPathList: allKeyPathList, sigstoreEnabled: sigstoreEnabled}
	} else if signType == SignedResourceTypeHelm {
		return &HelmVerifier{Namespace: dryRunNamespace, KeyPathList: pgpKeyPathList}
	}
	return nil
}

func (self *ResourceVerifier) Verify(sig *GeneralSignature, v2resc *common.V2ResourceContext, signingProfile rspapi.ResourceSigningProfile) (*SigVerifyResult, []string, error) {
	var vcerr *common.CheckError
	var vsinfo *common.SignerInfo
	var retErr error

	excludeDiffValue := v2resc.ExcludeDiffValue()

	kustomizeList := signingProfile.Kustomize(v2resc.Map())
	allowNSChange := false
	for _, k := range kustomizeList {
		if k.AllowNamespaceChange {
			allowNSChange = true
			break
		}
	}
	allowDiffPatterns := makeAllowDiffPatterns(v2resc, kustomizeList)

	protectAttrsList := signingProfile.ProtectAttrs(v2resc.Map())
	ignoreAttrsList := signingProfile.IgnoreAttrs(v2resc.Map())

	resSigUID := sig.data["resourceSignatureUID"]
	sigFrom := ""
	if resSigUID == "" {
		sigFrom = "annotation"
	} else {
		sigFrom = "ResourceSignature"
	}

	if sig.option["matchRequired"] {
		message, _ := sig.data["message"]
		// use yamlBytes if single yaml data is extracted from ResourceSignature
		if yamlBytes, ok := sig.data["yamlBytes"]; ok {
			message = yamlBytes
		}

		// if allowNamespaceChange is true in KustomizePattern, overwrite namespace in message with requested one
		if allowNSChange {
			messageNode, err := mapnode.NewFromYamlBytes([]byte(message))
			if err == nil {
				overwriteJson := fmt.Sprintf(`{"metadata":{"namespace":"%s"}}`, v2resc.Namespace)
				overwriteNode, _ := mapnode.NewFromBytes([]byte(overwriteJson))
				newMessageNode, err := messageNode.Merge(overwriteNode)
				if err == nil {
					message = newMessageNode.ToYaml()
				}
			}
		}

		matched, diffStr := self.MatchMessage([]byte(message), v2resc.RawObject, protectAttrsList, ignoreAttrsList, allowDiffPatterns, v2resc.ResourceScope, v2resc.Kind, sig.SignType, excludeDiffValue)
		if !matched {
			msg := fmt.Sprintf("The message for this signature in %s is not identical with the requested object. diff: %s", sigFrom, diffStr)
			return &SigVerifyResult{
				Error: &common.CheckError{
					Msg:    msg,
					Reason: msg,
					Error:  nil,
				},
				Signer: nil,
			}, []string{}, nil
		}
	}

	if sig.option["scopedSignature"] {
		isValidScopeSignature := false
		scopeDenyMsg := ""

		// TODO: support scopedSignature after refactoring
		// if reqc.IsCreateRequest() {
		// 	// for CREATE request, this boolean flag will be true.
		// 	// because signature verification will work as value check in the case of scopedSignature.
		// 	isValidScopeSignature = true
		// } else if reqc.IsUpdateRequest() {
		// 	// for UPDATE request, IShield will confirm that no value is modified except attributes in `scope`.
		// 	// if there is any modification, the request will be denied.
		// 	if reqc.OrgMetadata.Labels.IntegrityVerified() {
		// 		scope, _ := sig.data["scope"]
		// 		diffIsInMessageScope := self.IsPatchWithScopeKey(reqc.RawOldObject, reqc.RawObject, scope, excludeDiffValue)
		// 		if diffIsInMessageScope {
		// 			isValidScopeSignature = true
		// 		} else {
		// 			scopeDenyMsg = fmt.Sprintf("messageScope of the signature in %s does not cover all changed attributes in this update", sigFrom)
		// 		}
		// 	} else {
		// 		scopeDenyMsg = fmt.Sprintf("Original object must be integrityVerified to allow UPDATE request with scope signature specified in %s", sigFrom)
		// 	}
		// }
		if !isValidScopeSignature {
			return &SigVerifyResult{
				Error: &common.CheckError{
					Msg:    scopeDenyMsg,
					Reason: scopeDenyMsg,
					Error:  nil,
				},
				Signer: nil,
			}, []string{}, nil
		}
	}

	message := []byte(sig.data["message"])
	signature := []byte(sig.data["signature"])
	certificateStr, certFound := sig.data["certificate"]
	certificate := []byte(certificateStr)

	// To use your custom verifier, first implement Verify() function in "shield/pkg/util/sign/yourcustompackage" .
	// Then you can add your function here.
	verifiers := map[string]*sign.Verifier{
		"pgp":      sign.NewVerifier(pgp.Verify, self.PGPKeyPathList, sigFrom),
		"x509":     sign.NewVerifier(x509.Verify, self.X509CertPathList, sigFrom),
		"sigstore": sign.NewVerifier(sigstore.Verify, self.SigStoreCertPathList, sigFrom),
		// "custom": sign.NewVerifier(custom.Verify, nil, sigFrom),
	}
	certRequired := map[string]bool{
		"pgp":      false,
		"x509":     true,
		"sigstore": true,
	}

	verifiedKeyPathList := []string{}
	for sigType, verifier := range verifiers {
		// skip this verifier because no valid key path is configured
		if !verifier.HasAnyKey() {
			continue
		}
		// skip this because certificate is required for this verification but not found
		if certRequired[sigType] && !certFound {
			continue
		}
		// try verifying
		sigErr, sigInfo, okPathList := verifier.Verify(message, signature, certificate)
		vcerr = sigErr
		vsinfo = sigInfo
		verifiedKeyPathList = append(verifiedKeyPathList, okPathList...)
	}

	// additional pgp verification trial only for detail error message
	if vsinfo == nil {
		for _, keyPath := range self.AllMountedKeyPathList {
			if strings.Contains(keyPath, "/pgp/") {
				if ok2, signer2, _, _ := pgp.Verify(message, signature, nil, keyPath); ok2 && signer2 != nil {
					vsinfo = signer2
					break
				}
			}
		}
	}

	svresult := &SigVerifyResult{
		Error:  vcerr,
		Signer: vsinfo,
	}
	return svresult, verifiedKeyPathList, retErr
}

func (self *ResourceVerifier) MatchMessage(message, reqObj []byte, protectAttrs, ignoreAttrs []*common.AttrsPattern, allowDiffPatterns []*mapnode.DiffPattern, resScope, resKind string, signType SignedResourceType, excludeDiffValue bool) (bool, string) {
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
		for _, attrs := range ignoreAttrs {
			addMask = append(addMask, attrs.Attrs...)
		}
		mask = append(mask, addMask...)
	}

	// CASE1: direct matching
	matched, diffStr = matchContents(orgObj, reqObj, focus, mask, allowDiffPatterns, excludeDiffValue)
	if matched {
		logger.Debug("matched directly")
	}

	// do not attempt to DryRun for all Cluster scope resources
	// because ishield-sa does not have a role for creating "any" resource at cluster scope
	// currently IShield tries dry-run only for CRD request among cluster scope resources
	if resScope == "Cluster" {
		if resKind == "CustomResourceDefinition" {
			// for CRD, additional mask is required for dryrun
			addMask = append(addMask, "spec.names")
			addMask = append(addMask, "spec.validation")
			addMask = append(addMask, "spec.versions")
			addMask = append(addMask, "spec.version")
		} else {
			return matched, diffStr
		}
	}

	// CASE2: DryRun for create or for update by edit/replace
	if !matched {
		nsMaskedOrgBytes := orgNode.Mask([]string{"metadata.namespace"}).ToYaml()
		simObj, err := kubeutil.DryRunCreate([]byte(nsMaskedOrgBytes), self.dryRunNamespace)
		if err != nil {
			logger.Error(fmt.Sprintf("Error in DryRunCreate: %s", err.Error()))
			return false, ""
		}
		mask = getMaskDef("")
		mask = append(mask, addMask...)
		mask = append(mask, "metadata.name") // DryRunCreate() uses name like `<name>-dry-run` to avoid already exists error
		mask = append(mask, "status")        // DryRunCreate() may generate different status. this will be ignored.

		matched, diffStr = matchContents(simObj, reqObj, focus, mask, allowDiffPatterns, excludeDiffValue)
		if matched {
			logger.Debug("matched by DryRunCreate()")
		}
	}
	// CASE3: DryRun for update by apply
	if !matched {
		reqNode, _ := mapnode.NewFromBytes(reqObj)
		reqNamespace := reqNode.GetString("metadata.namespace")
		_, patchedBytes, err := kubeutil.GetApplyPatchBytes(orgObj, reqNamespace)
		if err != nil {
			logger.Error(fmt.Sprintf("Error in getting patched bytes: %s", err.Error()))
			return false, ""
		}
		patchedNode, _ := mapnode.NewFromBytes(patchedBytes)
		nsMaskedPatchedNode := patchedNode.Mask([]string{"metadata.namespace"})
		simPatchedObj, err := kubeutil.DryRunCreate([]byte(nsMaskedPatchedNode.ToYaml()), self.dryRunNamespace)
		if err != nil {
			logger.Error(fmt.Sprintf("Error in DryRunCreate for Patch: %s", err.Error()))
			return false, ""
		}
		mask = getMaskDef("")
		mask = append(mask, addMask...)
		mask = append(mask, "metadata.name") // DryRunCreate() uses name like `<name>-dry-run` to avoid already exists error
		mask = append(mask, "status")        // DryRunCreate() may generate different status. this will be ignored.
		matched, diffStr = matchContents(simPatchedObj, reqObj, focus, mask, allowDiffPatterns, excludeDiffValue)
		if matched {
			logger.Debug("matched by GetApplyPatchBytes()")
		}
	}
	// CASE4: DryRun for update by patch
	if !matched && signType == SignedResourceTypePatch {
		patchedBytes, err := kubeutil.StrategicMergePatch(reqObj, orgObj, "")
		if err != nil {
			logger.Error(fmt.Sprintf("Error in getting patched bytes: %s", err.Error()))
			return false, ""
		}
		patchedNode, _ := mapnode.NewFromBytes(patchedBytes)
		nsMaskedPatchedNode := patchedNode.Mask([]string{"metadata.namespace"})
		simPatchedObj, err := kubeutil.DryRunCreate([]byte(nsMaskedPatchedNode.ToYaml()), self.dryRunNamespace)
		if err != nil {
			logger.Error(fmt.Sprintf("Error in DryRunCreate for Patch: %s", err.Error()))
			return false, ""
		}
		mask = getMaskDef("")
		mask = append(mask, addMask...)
		mask = append(mask, "metadata.name") // DryRunCreate() uses name like `<name>-dry-run` to avoid already exists error
		mask = append(mask, "status")        // DryRunCreate() may generate different status. this will be ignored.
		matched, diffStr = matchContents(simPatchedObj, reqObj, focus, mask, allowDiffPatterns, excludeDiffValue)
		if matched {
			logger.Debug("matched by StrategicMergePatch()")
		}
	}
	return matched, diffStr
}

func (self *ResourceVerifier) IsPatchWithScopeKey(orgObj, rawObj []byte, scope string, excludeDiffValue bool) bool {
	var mask []string
	mask = getMaskDef("")
	scopeKeys := mapnode.SplitCommaSeparatedKeys(scope)
	mask = append(mask, scopeKeys...)
	matched, _ := matchContents(orgObj, rawObj, nil, mask, nil, excludeDiffValue)
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

func matchContents(orgObj, reqObj []byte, focus, mask []string, allowDiffPatterns []*mapnode.DiffPattern, excludeDiffValue bool) (bool, string) {
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
		if excludeDiffValue {
			diffStr = dr.KeyString()
		} else {
			diffStr = dr.String()
		}
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

func makeAllowDiffPatterns(v2resc *common.V2ResourceContext, kustomizeList []*common.KustomizePattern) []*mapnode.DiffPattern {
	ref := v2resc.ResourceRef()
	name := v2resc.Name
	kustomizedName := name
	for _, pattern := range kustomizeList {
		newRef := pattern.Override(ref)
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
	allowDiffPattern := &mapnode.DiffPattern{
		Key:    key,
		Values: values,
	}
	return []*mapnode.DiffPattern{allowDiffPattern}
}

type SigVerifyResult struct {
	Error  *common.CheckError
	Signer *common.SignerInfo
}

/**********************************************

				HelmVerifier

***********************************************/

type HelmVerifier struct {
	Namespace   string
	KeyPathList []string
}

func (self *HelmVerifier) Verify(sig *GeneralSignature, v2resc *common.V2ResourceContext, signingProfile rspapi.ResourceSigningProfile) (*SigVerifyResult, []string, error) {
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
			}, []string{}, nil
		}
	}

	// verify helm chart with prov in HelmReleaseMetadata.
	// helm provenance supports only PGP Verification.
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

	svresult := &SigVerifyResult{
		Error:  vcerr,
		Signer: vsinfo,
	}
	return svresult, []string{}, retErr

}

var CommonMessageMask = []string{
	fmt.Sprintf("metadata.labels.\"%s\"", common.ResourceIntegrityLabelKey),
	fmt.Sprintf("metadata.annotations.\"%s\"", common.SignedByAnnotationKey),
	fmt.Sprintf("metadata.annotations.\"%s\"", common.LastVerifiedTimestampAnnotationKey),
	fmt.Sprintf("metadata.annotations.\"%s\"", common.ResourceSignatureUIDAnnotationKey),
	fmt.Sprintf("metadata.annotations.\"%s\"", common.SignatureAnnotationKey),
	fmt.Sprintf("metadata.annotations.\"%s\"", common.MessageAnnotationKey),
	fmt.Sprintf("metadata.annotations.\"%s\"", common.CertificateAnnotationKey),
	fmt.Sprintf("metadata.annotations.\"%s\"", common.SignatureTypeAnnotationKey),
	fmt.Sprintf("metadata.annotations.\"%s\"", common.MessageScopeAnnotationKey),
	fmt.Sprintf("metadata.annotations.\"%s\"", common.MutableAttrsAnnotationKey),
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
	"status",
}
