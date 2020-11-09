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
	"encoding/json"
	"fmt"

	vrsig "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/resourcesignature/v1alpha1"
	common "github.com/IBM/integrity-enforcer/enforcer/pkg/common/common"
	policy "github.com/IBM/integrity-enforcer/enforcer/pkg/common/policy"
	profile "github.com/IBM/integrity-enforcer/enforcer/pkg/common/profile"
	config "github.com/IBM/integrity-enforcer/enforcer/pkg/enforcer/config"
	helm "github.com/IBM/integrity-enforcer/enforcer/pkg/plugins/helm"
	logger "github.com/IBM/integrity-enforcer/enforcer/pkg/util/logger"
)

type VerifyType string
type SignatureType string

const (
	VerifyTypeX509 VerifyType = "x509"
	VerifyTypePGP  VerifyType = "pgp"
)

const (
	SignatureTypeUnknown          SignatureType = ""
	SignatureTypeResource         SignatureType = "Resource"
	SignatureTypeApplyingResource SignatureType = "ApplyingResource"
	SignatureTypePatch            SignatureType = "Patch"
	SignatureTypeHelm             SignatureType = "Helm"
)

/**********************************************

				GeneralSignature

***********************************************/

type GeneralSignature struct {
	SignType SignatureType
	data     map[string]string
	option   map[string]bool
}

/**********************************************

				Signature

***********************************************/

type SignatureEvaluator interface {
	Eval(reqc *common.ReqContext, resSigList *vrsig.ResourceSignatureList, signingProfile profile.SigningProfile) (*common.SignatureEvalResult, error)
}

type ConcreteSignatureEvaluator struct {
	config  *config.EnforcerConfig
	policy  *policy.SignPolicy
	plugins map[string]bool
}

func NewSignatureEvaluator(config *config.EnforcerConfig, policy *policy.SignPolicy, plugins map[string]bool) (SignatureEvaluator, error) {
	return &ConcreteSignatureEvaluator{
		config:  config,
		policy:  policy,
		plugins: plugins,
	}, nil
}

func (self *ConcreteSignatureEvaluator) GetResourceSignature(ref *common.ResourceRef, reqc *common.ReqContext, resSigList *vrsig.ResourceSignatureList) *GeneralSignature {

	sigAnnotations := reqc.ClaimedMetadata.Annotations.SignatureAnnotations()

	//1. pick ResourceSignature from metadata.annotation if available
	if sigAnnotations.Signature != "" {
		message := base64decode(sigAnnotations.Message)
		message = decompress(message)
		messageScope := sigAnnotations.MessageScope
		mutableAttrs := sigAnnotations.MutableAttrs
		matchRequired := true
		scopedSignature := false
		if message == "" && messageScope != "" {
			message = GenerateMessageFromRawObj(reqc.RawObject, messageScope, mutableAttrs)
			matchRequired = false  // skip matching because the message is generated from Requested Object
			scopedSignature = true // enable checking if the signature is for patch
		}
		signature := base64decode(sigAnnotations.Signature)
		certificate := base64decode(sigAnnotations.Certificate)
		signType := SignatureTypeResource
		if sigAnnotations.SignatureType == vrsig.SignatureTypeApplyingResource {
			signType = SignatureTypeApplyingResource
		} else if sigAnnotations.SignatureType == vrsig.SignatureTypePatch {
			signType = SignatureTypePatch
		}
		return &GeneralSignature{
			SignType: signType,
			data:     map[string]string{"signature": signature, "message": message, "certificate": certificate, "scope": messageScope},
			option:   map[string]bool{"matchRequired": matchRequired, "scopedSignature": scopedSignature},
		}
	}

	//2. pick ResourceSignature from custom resource if available
	if resSigList != nil && len(resSigList.Items) > 0 {
		si, yamlBytes, found := resSigList.FindSignItem(ref.ApiVersion, ref.Kind, ref.Name, ref.Namespace)
		if found {
			signature := base64decode(si.Signature)
			certificate := base64decode(si.Certificate)
			message := base64decode(si.Message)
			message = decompress(message)
			mutableAttrs := si.MutableAttrs
			matchRequired := true
			scopedSignature := false
			if si.Message == "" && si.MessageScope != "" {
				message = GenerateMessageFromRawObj(reqc.RawObject, si.MessageScope, mutableAttrs)
				matchRequired = false  // skip matching because the message is generated from Requested Object
				scopedSignature = true // enable checking if the signature is for patch
			}
			signType := SignatureTypeResource
			if si.Type == vrsig.SignatureTypeApplyingResource {
				signType = SignatureTypeApplyingResource
			} else if si.Type == vrsig.SignatureTypePatch {
				signType = SignatureTypePatch
			}
			return &GeneralSignature{
				SignType: signType,
				data:     map[string]string{"signature": signature, "message": message, "certificate": certificate, "yamlBytes": string(yamlBytes), "scope": si.MessageScope},
				option:   map[string]bool{"matchRequired": matchRequired, "scopedSignature": scopedSignature},
			}
		}
	}

	//3. pick ResourceSignature from external store if available

	//4. helm resource (release secret, helm cahrt resources)
	if ok := self.plugins["helm"]; ok {
		rsecBytes, err := helm.FindReleaseSecret(reqc.Namespace, reqc.Kind, reqc.Name, reqc.RawObject)
		if err != nil {
			logger.Error(fmt.Sprintf("Error occured in finding helm release secret; %s", err.Error()))
			return nil
		}
		if rsecBytes != nil {
			hrmSigs, err := helm.GetHelmReleaseMetadata(rsecBytes)
			if err == nil && len(hrmSigs) == 2 {
				rls := hrmSigs[0]
				hrm := hrmSigs[1]
				eCfg := true

				return &GeneralSignature{
					SignType: SignatureTypeHelm,
					data:     map[string]string{"releaseSecret": rls, "helmReleaseMetadata": hrm},
					option:   map[string]bool{"emptyConfig": eCfg, "matchRequired": true},
				}
			} else {
				logger.Error(fmt.Sprintf("Error occured in getting signature from helm release metadata; %s", err.Error()))
				return nil

			}
		}
	}
	return nil

	//5. return nil if no signature found
	// return nil
}

func (self *ConcreteSignatureEvaluator) Eval(reqc *common.ReqContext, resSigList *vrsig.ResourceSignatureList, signingProfile profile.SigningProfile) (*common.SignatureEvalResult, error) {

	// eval sign policy
	ref := reqc.ResourceRef()

	// override ref name if there is kustomize pattern for this
	kustPatterns := signingProfile.Kustomize(reqc.Map())
	if len(kustPatterns) > 0 {
		ref = kustPatterns[0].OverrideName(ref)
	}

	// find signature
	rsig := self.GetResourceSignature(ref, reqc, resSigList)
	if rsig == nil {
		return &common.SignatureEvalResult{
			Allow:   false,
			Checked: true,
			Error: &common.CheckError{
				Reason: "No signature found",
			},
		}, nil
	}

	verifyType := VerifyType(self.config.VerifyType)
	candidatePubkeys := self.policy.GetCandidatePubkeys(self.config.KeyPathList, reqc.Namespace)

	// create verifier
	verifier := NewVerifier(verifyType, rsig.SignType, self.config.Namespace, candidatePubkeys)

	// verify signature
	sigVerifyResult, err := verifier.Verify(rsig, reqc, signingProfile)
	if err != nil {
		return &common.SignatureEvalResult{
			Allow:   false,
			Checked: true,
			Error: &common.CheckError{
				Error:  err,
				Reason: "Error during signature verification",
			},
		}, nil
	}

	if sigVerifyResult == nil || sigVerifyResult.Signer == nil {
		msg := ""
		if sigVerifyResult != nil && sigVerifyResult.Error != nil {
			msg = sigVerifyResult.Error.Reason
		}
		return &common.SignatureEvalResult{
			Allow:   false,
			Checked: true,
			Error: &common.CheckError{
				Reason: fmt.Sprintf("Failed to verify signature; %s", msg),
			},
		}, nil
	}

	// signer
	signer := sigVerifyResult.Signer

	// check signer policy
	signerMatched, matchedPolicy := self.policy.Match(reqc.Namespace, signer)
	if signerMatched {
		matchedPolicyStr := ""
		if matchedPolicy != nil {
			tmpMatchedPolicy, _ := json.Marshal(matchedPolicy)
			matchedPolicyStr = string(tmpMatchedPolicy)
		}
		return &common.SignatureEvalResult{
			Signer:        signer,
			SignerName:    signer.GetName(),
			Allow:         true,
			Checked:       true,
			MatchedPolicy: matchedPolicyStr,
			Error:         nil,
		}, nil
	} else {
		return &common.SignatureEvalResult{
			Signer:     signer,
			SignerName: signer.GetName(),
			Allow:      false,
			Checked:    true,
			Error: &common.CheckError{
				Reason: fmt.Sprintf("No signer policies met this resource. this resource is signed by %s", signer.GetName()),
			},
		}, nil
	}
}

func findAttrsPattern(reqc *common.ReqContext, attrs []*profile.AttrsPattern) []string {
	reqFields := reqc.Map()
	masks := []string{}
	for _, attr := range attrs {
		if attr.MatchWith(reqFields) {
			masks = append(masks, attr.Attrs...)
		}
	}
	return masks
}
