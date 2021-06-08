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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	corev1 "k8s.io/api/core/v1"

	vrsig "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesignature/v1alpha1"
	rspapi "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesigningprofile/v1alpha1"
	common "github.com/IBM/integrity-enforcer/shield/pkg/common"
	config "github.com/IBM/integrity-enforcer/shield/pkg/config"
	helm "github.com/IBM/integrity-enforcer/shield/pkg/plugins/helm"
	image "github.com/IBM/integrity-enforcer/shield/pkg/util/image"
	"github.com/IBM/integrity-enforcer/shield/pkg/util/kubeutil"
	logger "github.com/IBM/integrity-enforcer/shield/pkg/util/logger"
	pgp "github.com/IBM/integrity-enforcer/shield/pkg/util/sign/pgp"
	"github.com/IBM/integrity-enforcer/shield/pkg/util/sign/sigstore"
	x509 "github.com/IBM/integrity-enforcer/shield/pkg/util/sign/x509"
	ishieldyaml "github.com/IBM/integrity-enforcer/shield/pkg/util/yaml"
)

type SignedResourceType string

const (
	SignedResourceTypeUnknown          SignedResourceType = ""
	SignedResourceTypeResource         SignedResourceType = "Resource"
	SignedResourceTypeApplyingResource SignedResourceType = "ApplyingResource"
	SignedResourceTypePatch            SignedResourceType = "Patch"
	SignedResourceTypeHelm             SignedResourceType = "Helm"
)

/**********************************************

                GeneralSignature

***********************************************/

type GeneralSignature struct {
	SignType SignedResourceType
	data     map[string]string
	option   map[string]bool
}

/**********************************************

                Signature

***********************************************/

type SignatureEvaluator interface {
	Eval(resc *common.ResourceContext, resSigList *vrsig.ResourceSignatureList) (*common.SignatureEvalResult, error)
}

type ConcreteSignatureEvaluator struct {
	config            *config.ShieldConfig
	profileParameters rspapi.Parameters
	plugins           map[string]bool
}

func NewSignatureEvaluator(config *config.ShieldConfig, profileParameters rspapi.Parameters, plugins map[string]bool) (SignatureEvaluator, error) {
	return &ConcreteSignatureEvaluator{
		config:            config,
		profileParameters: profileParameters,
		plugins:           plugins,
	}, nil
}

func (self *ConcreteSignatureEvaluator) GetResourceSignature(ref *common.ResourceRef, resc *common.ResourceContext, resSigList *vrsig.ResourceSignatureList) *GeneralSignature {

	sigAnnotations := resc.ClaimedMetadata.Annotations.SignatureAnnotations()

	//1. pick ResourceSignature from metadata.annotation if available
	if sigAnnotations.Signature != "" {
		found, yamlBytes := ishieldyaml.FindSingleYaml([]byte(sigAnnotations.Message), ref.ApiVersion, ref.Kind, ref.Name, ref.Namespace)
		if found {
			message := ishieldyaml.Base64decode(sigAnnotations.Message)
			message = ishieldyaml.Decompress(message)
			messageScope := sigAnnotations.MessageScope
			mutableAttrs := sigAnnotations.MutableAttrs
			matchRequired := true
			scopedSignature := false
			if message == "" && messageScope != "" {
				message = GenerateMessageFromRawObj(resc.RawObject, messageScope, mutableAttrs)
				matchRequired = false  // skip matching because the message is generated from Requested Object
				scopedSignature = true // enable checking if the signature is for patch
			}
			signature := ishieldyaml.Base64decode(sigAnnotations.Signature)
			certificate := ishieldyaml.Base64decode(sigAnnotations.Certificate)
			certificate = ishieldyaml.Decompress(certificate)
			sigstoreBundle := ""
			if sigAnnotations.SigStoreBundle != "" {
				sigstoreBundle = ishieldyaml.Base64decode(sigAnnotations.SigStoreBundle)
				sigstoreBundle = ishieldyaml.Decompress(sigstoreBundle)
			}
			signType := SignedResourceTypeResource
			if sigAnnotations.SignatureType == vrsig.SignatureTypeApplyingResource {
				signType = SignedResourceTypeApplyingResource
			} else if sigAnnotations.SignatureType == vrsig.SignatureTypePatch {
				signType = SignedResourceTypePatch
			}
			return &GeneralSignature{
				SignType: signType,
				data:     map[string]string{"signature": signature, "message": message, "certificate": certificate, "yamlBytes": string(yamlBytes), "scope": messageScope, "sigstoreBundle": sigstoreBundle},
				option:   map[string]bool{"matchRequired": matchRequired, "scopedSignature": scopedSignature},
			}
		}
	}

	//2. pick ResourceSignature from custom resource if available
	if resSigList != nil && len(resSigList.Items) > 0 {
		found, si, yamlBytes, resSigUID := resSigList.FindSignItem(ref.ApiVersion, ref.Kind, ref.Name, ref.Namespace)
		if found {
			signature := ishieldyaml.Base64decode(si.Signature)
			certificate := ishieldyaml.Base64decode(si.Certificate)
			certificate = ishieldyaml.Decompress(certificate)
			sigstoreBundle := ""
			if si.SigStoreBundle != "" {
				sigstoreBundle = ishieldyaml.Base64decode(si.SigStoreBundle)
				sigstoreBundle = ishieldyaml.Decompress(sigstoreBundle)
			}
			message := ishieldyaml.Base64decode(si.Message)
			message = ishieldyaml.Decompress(message)
			mutableAttrs := si.MutableAttrs
			matchRequired := true
			scopedSignature := false
			if si.Message == "" && si.MessageScope != "" {
				message = GenerateMessageFromRawObj(resc.RawObject, si.MessageScope, mutableAttrs)
				matchRequired = false  // skip matching because the message is generated from Requested Object
				scopedSignature = true // enable checking if the signature is for patch
			}
			signType := SignedResourceTypeResource
			if si.Type == vrsig.SignatureTypeApplyingResource {
				signType = SignedResourceTypeApplyingResource
			} else if si.Type == vrsig.SignatureTypePatch {
				signType = SignedResourceTypePatch
			}
			return &GeneralSignature{
				SignType: signType,
				data:     map[string]string{"signature": signature, "message": message, "certificate": certificate, "yamlBytes": string(yamlBytes), "scope": si.MessageScope, "sigstoreBundle": sigstoreBundle, "resourceSignatureUID": resSigUID},
				option:   map[string]bool{"matchRequired": matchRequired, "scopedSignature": scopedSignature},
			}
		}
	}

	//3. pick Signature from OCI registry if available
	manifestImageRef := ""
	if manifestImageRef == "" && sigAnnotations.ManifestImageRef != "" {
		manifestImageRef = sigAnnotations.ManifestImageRef
	}
	if manifestImageRef == "" && self.profileParameters.ManifestReference != nil {
		manifestImageRef = self.profileParameters.ManifestReference.Image
	}
	if manifestImageRef != "" {
		img, err := image.PullImage(manifestImageRef)
		var concatYAMLBytes []byte
		if err != nil {
			logger.Error("failed to pull image: ", err.Error())
		} else {
			concatYAMLBytes, err = image.GenerateConcatYAMLsFromImage(img)
			if err != nil {
				logger.Error("failed to generate concat yaml from image: ", err.Error())
			}
		}
		fmt.Println("[DEBUG] concatYAMLBytes in image:\n", string(concatYAMLBytes))
		found, yamlBytes := ishieldyaml.FindSingleYaml(concatYAMLBytes, ref.ApiVersion, ref.Kind, ref.Name, ref.Namespace)
		fmt.Println("[DEBUG] found yamlBytes in image:\n", string(yamlBytes))

		if found {
			signType := SignedResourceTypeResource
			matchRequired := true
			scopedSignature := false
			verifyWithImage := true
			return &GeneralSignature{
				SignType: signType,
				data:     map[string]string{"imageRef": manifestImageRef, "yamlBytes": string(yamlBytes)},
				option:   map[string]bool{"matchRequired": matchRequired, "scopedSignature": scopedSignature, "verifyWithImage": verifyWithImage},
			}
		}
	}

	//4. helm resource (release secret, helm cahrt resources)
	if ok := self.plugins["helm"]; ok {
		rsecBytes, err := helm.FindReleaseSecret(resc.Namespace, resc.Kind, resc.Name, resc.RawObject)
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
					SignType: SignedResourceTypeHelm,
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

func (self *ConcreteSignatureEvaluator) Eval(resc *common.ResourceContext, resSigList *vrsig.ResourceSignatureList) (*common.SignatureEvalResult, error) {

	// eval sign policy
	ref := resc.ResourceRef()

	// find signature
	rsig := self.GetResourceSignature(ref, resc, resSigList)
	if rsig == nil {
		return &common.SignatureEvalResult{
			Allow:   false,
			Checked: true,
			Error: &common.CheckError{
				Reason: common.ReasonCodeMap[common.REASON_NO_SIG].Message,
			},
		}, nil
	}
	rsigUID := rsig.data["resourceSignatureUID"] // this will be empty string if annotation signature

	signerConfig := self.profileParameters.SignerConfig
	originalCandidatePubkeys := signerConfig.GetCandidatePubkeys(self.config.Namespace)

	// if this verification is not executed in a K8s pod (e.g. using ishieldctl command), then try loading secrets for pubkeys
	overwriteSecretsBaseDir := ""
	if !kubeutil.IsInCluster() {
		// for the testcases & the case this is called from CLI
		overwriteSecretsBaseDir = "./tmp"
	}
	// load secrets if not there and update the path for some cases above
	// TODO: apply TTL for saved secret to support updating pubkey secret
	candidatePubkeys, err := loadSecrets(originalCandidatePubkeys, overwriteSecretsBaseDir)
	if err != nil {
		logger.Warn("Error while loading pubkey/certificate secrets;", err.Error())
	}

	pgpPubkeys := candidatePubkeys[common.SignatureTypePGP]
	x509Certs := candidatePubkeys[common.SignatureTypeX509]
	sigstoreCerts := candidatePubkeys[common.SignatureTypeSigStore]

	sigstoreEnabled := self.config.SigStoreEnabled()

	// create verifier
	dryRunNamespace := ""
	if resc.ResourceScope == string(common.ScopeNamespaced) {
		dryRunNamespace = self.config.Namespace
	}
	verifier := NewVerifier(rsig.SignType, dryRunNamespace, pgpPubkeys, x509Certs, sigstoreCerts, self.config.KeyPathList, sigstoreEnabled)

	keyLoadingError := false
	candidateKeyCount := len(pgpPubkeys) + len(x509Certs)
	if candidateKeyCount > 0 {
		validKeyCount := 0
		for _, keyPath := range pgpPubkeys {
			if loaded, _ := pgp.LoadKeyRingDir(keyPath); len(loaded) > 0 {
				validKeyCount += 1
			}
		}

		for _, certDir := range x509Certs {
			if loaded, _ := x509.LoadCertDir(certDir); len(loaded) > 0 {
				validKeyCount += 1
			}
		}

		for _, certPath := range sigstoreCerts {
			if loaded, _ := sigstore.LoadCertPoolDir(certPath); loaded != nil {
				validKeyCount += 1
			}
		}
		if validKeyCount == 0 {
			keyLoadingError = true
		}
	}

	// verify signature
	sigVerifyResult, verifiedKeyPathList, err := verifier.Verify(rsig, resc, self.profileParameters)
	if err != nil {
		reasonFail := fmt.Sprintf("Error during signature verification; %s; %s", sigVerifyResult.Error.Reason, err.Error())
		return &common.SignatureEvalResult{
			Allow:   false,
			Checked: true,
			Error: &common.CheckError{
				Error:  err,
				Reason: reasonFail,
			},
			ResourceSignatureUID: rsigUID,
		}, nil
	}

	if keyLoadingError {
		reasonFail := common.ReasonCodeMap[common.REASON_NO_VALID_KEYRING].Message
		return &common.SignatureEvalResult{
			Allow:   false,
			Checked: true,
			Error: &common.CheckError{
				Reason: reasonFail,
			},
			ResourceSignatureUID: rsigUID,
		}, nil
	}

	if sigVerifyResult == nil || sigVerifyResult.Signer == nil {
		reasonFail := common.ReasonCodeMap[common.REASON_INVALID_SIG].Message
		if sigVerifyResult != nil && sigVerifyResult.Error != nil {
			reasonFail = fmt.Sprintf("%s; %s", reasonFail, sigVerifyResult.Error.Reason)
		}
		return &common.SignatureEvalResult{
			Allow:   false,
			Checked: true,
			Error: &common.CheckError{
				Reason: reasonFail,
			},
			ResourceSignatureUID: rsigUID,
		}, nil
	}

	// signer
	signer := sigVerifyResult.Signer

	// check signer config
	signerMatched, matchedSignerCondition := signerConfig.Match(signer, verifiedKeyPathList, self.config.Namespace)
	if signerMatched {
		matchedSignerConditionStr := ""
		if matchedSignerCondition != nil {
			tmpMatchedCondition, _ := json.Marshal(matchedSignerCondition)
			matchedSignerConditionStr = string(tmpMatchedCondition)
		}
		return &common.SignatureEvalResult{
			Signer:               signer,
			SignerName:           signer.GetName(),
			Allow:                true,
			Checked:              true,
			MatchedSignerConfig:  matchedSignerConditionStr,
			Error:                nil,
			ResourceSignatureUID: rsigUID,
		}, nil
	} else {
		reasonFail := common.ReasonCodeMap[common.REASON_NO_MATCH_SIGNER_CONFIG].Message
		if signer != nil {
			reasonFail = fmt.Sprintf("%s; This resource is signed by %s", reasonFail, signer.GetNameWithFingerprint())
		}
		return &common.SignatureEvalResult{
			Signer:     signer,
			SignerName: signer.GetName(),
			Allow:      false,
			Checked:    true,
			Error: &common.CheckError{
				Reason: reasonFail,
			},
			ResourceSignatureUID: rsigUID,
		}, nil
	}
}

func findAttrsPattern(reqc *common.RequestContext, resc *common.ResourceContext, attrs []*common.AttrsPattern) []string {
	reqFields := resc.Map()
	masks := []string{}
	for _, attr := range attrs {
		if attr.MatchWith(reqFields) {
			masks = append(masks, attr.Attrs...)
		}
	}
	return masks
}

func loadSecrets(candidatePubkeys map[common.SignatureType][]string, overwriteSecretsBaseDir string) (map[common.SignatureType][]string, error) {
	replace := map[string]string{}
	for _, keyPathList := range candidatePubkeys {
		for _, keyPath := range keyPathList {
			// if secret is found, skip loading
			if exists(keyPath) {
				continue
			}
			// otherwise, try getting secret and save it as tmp local file, and then update keyPathList at the end
			keyPathParts := parseKeyPath(keyPath)
			secretName := keyPathParts["secretName"]
			secretNamespace := keyPathParts["secretNamespace"]
			if secretName == "" {
				continue
			}
			// get secret
			obj, err := kubeutil.GetResource("v1", "Secret", secretNamespace, secretName)
			if err != nil {
				logger.Warn(fmt.Sprintf("Failed to get secret `%s`; %s", secretName, err.Error()))
				continue
			}
			objBytes, _ := json.Marshal(obj)
			var res corev1.Secret
			_ = json.Unmarshal(objBytes, &res)

			// save it in a tmp dir
			if overwriteSecretsBaseDir != "" {
				keyPathParts["base"] = overwriteSecretsBaseDir
			}
			newPath := filepath.Clean(joinKeyPathParts(keyPathParts))
			newPathDir := newPath
			if keyPathParts["file"] != "" {
				newPathDir = filepath.Dir(newPath)
			}
			err = os.MkdirAll(newPathDir, 0755)
			if err != nil {
				logger.Warn(fmt.Sprintf("Failed to create a directory for secret `%s`; %s", secretName, err.Error()))
				continue
			}
			for filename, pubKeyBytes := range res.Data {
				savingFilePath := filepath.Join(newPathDir, filename)
				err = ioutil.WriteFile(savingFilePath, pubKeyBytes, 0755)
				if err != nil {
					logger.Warn(fmt.Sprintf("Failed to save a secret as a file `%s`; %s", secretName, err.Error()))
					continue
				}
			}

			replace[keyPath] = newPathDir
		}
	}

	// replace all key path list with the saved filepath
	newCandidatePubkeys := map[common.SignatureType][]string{}
	for sigType, keyPathList := range candidatePubkeys {
		newKeyPathList := []string{}
		for _, keyPath := range keyPathList {
			newPath, ok := replace[keyPath]
			if !ok {
				newPath = keyPath
			}
			newKeyPathList = append(newKeyPathList, newPath)
		}
		newCandidatePubkeys[sigType] = newKeyPathList
	}
	return newCandidatePubkeys, nil
}

func parseKeyPath(keyPath string) map[string]string {
	m := map[string]string{
		"base":            "",
		"secretNamespace": "",
		"secretName":      "",
		"sigType":         "",
		"file":            "",
	}
	sigType := ""
	if strings.HasSuffix(keyPath, "/pgp") {
		sigType = "/pgp"
	} else if strings.HasSuffix(keyPath, "/x509") {
		sigType = "/x509"
	} else if strings.HasSuffix(keyPath, "/sigstore") {
		sigType = "/sigstore"
	}
	if sigType == "" {
		return m
	}

	m["sigType"] = sigType
	parts1 := strings.Split(keyPath, sigType)
	parts2 := strings.Split(parts1[0], "/")
	if len(parts1) >= 2 {
		m["file"] = parts1[1]
	}
	if len(parts2) >= 1 {
		m["secretName"] = parts2[len(parts2)-1]
	}
	secretNamespace := ""
	if len(parts2) >= 2 {
		secretNamespace = parts2[len(parts2)-2]
	}

	if secretNamespace == "" {
		return m
	}

	m["secretNamespace"] = secretNamespace
	parts3 := strings.Split(keyPath, secretNamespace)
	if len(parts2) >= 1 {
		m["base"] = parts3[0]
	}
	return m
}

func joinKeyPathParts(m map[string]string) string {
	keys := []string{"base", "secretNamespace", "secretName", "sigType", "file"}
	parts := []string{}
	for _, key := range keys {
		if v, ok := m[key]; ok {
			parts = append(parts, v)
		} else {
			return ""
		}
	}
	return strings.Join(parts, "/")
}

func exists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}
