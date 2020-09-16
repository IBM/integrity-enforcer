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

	vrsig "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/vresourcesignature/v1alpha1"
	"github.com/IBM/integrity-enforcer/enforcer/pkg/config"
	common "github.com/IBM/integrity-enforcer/enforcer/pkg/control/common"
	helm "github.com/IBM/integrity-enforcer/enforcer/pkg/helm"
	logger "github.com/IBM/integrity-enforcer/enforcer/pkg/logger"
	policy "github.com/IBM/integrity-enforcer/enforcer/pkg/policy"
	"github.com/jinzhu/copier"
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

				SignPolicy

***********************************************/

// TODO: change this to evaluator, Eval(reqc, resSigList) or

type SignPolicyEvaluator interface {
	Eval(reqc *common.ReqContext, resSigList *vrsig.VResourceSignatureList) (*common.SignPolicyEvalResult, error)
}

type ConcreteSignPolicyEvaluator struct {
	config  *config.EnforcerConfig
	policy  *policy.VSignPolicy
	plugins map[string]bool
}

func NewSignPolicyEvaluator(config *config.EnforcerConfig, policy *policy.VSignPolicy, plugins map[string]bool) (SignPolicyEvaluator, error) {
	return &ConcreteSignPolicyEvaluator{
		config:  config,
		policy:  policy,
		plugins: plugins,
	}, nil
}

func (self *ConcreteSignPolicyEvaluator) GetResourceSignature(ref *common.ResourceRef, reqc *common.ReqContext, resSigList *vrsig.VResourceSignatureList) *GeneralSignature {

	sigAnnotations := reqc.ClaimedMetadata.Annotations.SignatureAnnotations()

	//1. pick ResourceSignature from metadata.annotation if available
	if sigAnnotations.Signature != "" {
		message := base64decode(sigAnnotations.Message)
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
			data:     map[string]string{"signature": signature, "message": message, "certificate": certificate, "scope": messageScope, "mutableAttrs": mutableAttrs},
			option:   map[string]bool{"matchRequired": matchRequired, "scopedSignature": scopedSignature},
		}
	}

	//2. pick ResourceSignature from custom resource if available
	if resSigList != nil && len(resSigList.Items) > 0 {
		si, _, found := resSigList.FindSignItem(ref.ApiVersion, ref.Kind, ref.Name, ref.Namespace)
		if found {
			signature := base64decode(si.Signature)
			certificate := base64decode(si.Certificate)
			message := base64decode(si.Message)
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
				data:     map[string]string{"signature": signature, "message": message, "certificate": certificate, "scope": si.MessageScope, "mutableAttrs": mutableAttrs},
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
			if err == nil {
				message := hrmSigs[0]
				signature := hrmSigs[1]
				certificate := hrmSigs[2]
				rls := hrmSigs[3]
				hrm := hrmSigs[4]
				eCfg := true
				return &GeneralSignature{
					SignType: SignatureTypeHelm,
					data:     map[string]string{"message": message, "signature": signature, "certificate": certificate, "releaseSecret": rls, "helmReleaseMetadata": hrm},
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

func (self *ConcreteSignPolicyEvaluator) Eval(reqc *common.ReqContext, resSigList *vrsig.VResourceSignatureList) (*common.SignPolicyEvalResult, error) {

	if reqc.IsResourceSignatureRequest() {
		var rsigObj *vrsig.VResourceSignature
		json.Unmarshal(reqc.RawObject, &rsigObj)
		if ok, reasonFail := rsigObj.Validate(); !ok {
			return &common.SignPolicyEvalResult{
				Allow:   false,
				Checked: true,
				Error: &common.CheckError{
					Reason: fmt.Sprintf("Schema Error for %s; %s", common.SignatureCustomResourceKind, reasonFail),
				},
			}, nil
		}
	}

	// eval sign policy
	ref := reqc.ResourceRef()

	// find signature
	rsig := self.GetResourceSignature(ref, reqc, resSigList)
	if rsig == nil {
		return &common.SignPolicyEvalResult{
			Allow:   false,
			Checked: true,
			Error: &common.CheckError{
				Reason: "No signature found",
			},
		}, nil
	}

	verifyType := VerifyType(self.config.VerifyType)

	// create verifier
	verifier := NewVerifier(verifyType, rsig.SignType, self.config.Namespace, self.config.CertPoolPath, self.config.KeyringPath)

	// verify signature
	sigVerifyResult, err := verifier.Verify(rsig, reqc)
	if err != nil {
		return &common.SignPolicyEvalResult{
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
		return &common.SignPolicyEvalResult{
			Allow:   false,
			Checked: true,
			Error: &common.CheckError{
				Reason: fmt.Sprintf("Failed to verify signature; %s", msg),
			},
		}, nil
	}

	// signer
	signer := sigVerifyResult.Signer

	reqcForEval := makeReqcForEval(reqc, reqc.RawObject)

	// check signer policy
	signerMatched, matchedPolicy := self.policy.Match(reqcForEval.Namespace, signer)
	matchedPolicyStr := ""
	if matchedPolicy != nil {
		tmpMatchedPolicy, _ := json.Marshal(matchedPolicy)
		matchedPolicyStr = string(tmpMatchedPolicy)
	}
	if signerMatched {
		return &common.SignPolicyEvalResult{
			Signer:        signer,
			SignerName:    signer.GetName(),
			Allow:         true,
			Checked:       true,
			MatchedPolicy: matchedPolicyStr,
			Error:         nil,
		}, nil
	} else {
		return &common.SignPolicyEvalResult{
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

func makeReqcForEval(reqc *common.ReqContext, rawObj []byte) *common.ReqContext {
	var err error
	isResourceSignature := reqc.IsResourceSignatureRequest()

	if !isResourceSignature {
		return reqc
	}

	reqcForEval := &common.ReqContext{}
	copier.Copy(&reqcForEval, &reqc)

	if isResourceSignature {
		var rsigObj *vrsig.VResourceSignature
		err = json.Unmarshal(rawObj, &rsigObj)
		if err == nil {

			// TODO: override namespace with Parsed message in ResSig

			// if rsigObj.Spec.Data[0].Metadata.Namespace != "" {
			// 	reqcForEval.Namespace = rsigObj.Spec.Data[0].Metadata.Namespace
			// }
		} else {
			logger.Error(err)
		}
	}
	return reqcForEval
}
