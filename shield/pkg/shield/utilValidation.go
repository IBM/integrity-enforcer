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
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	hrm "github.com/IBM/integrity-enforcer/shield/pkg/apis/helmreleasemetadata/v1alpha1"
	rsig "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesignature/v1alpha1"
	rsp "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesigningprofile/v1alpha1"
	sconf "github.com/IBM/integrity-enforcer/shield/pkg/apis/shieldconfig/v1alpha1"
	sigconf "github.com/IBM/integrity-enforcer/shield/pkg/apis/signerconfig/v1alpha1"
	common "github.com/IBM/integrity-enforcer/shield/pkg/common"
)

func ValidateResource(reqc *common.ReqContext, shieldNamespace string) (bool, string) {
	if reqc.IsDeleteRequest() {
		return true, ""
	}

	if reqc.Kind == common.ProfileCustomResourceKind {
		ok, err := ValidateResourceSigningProfile(reqc, shieldNamespace)
		if err != nil {
			return false, fmt.Sprintf("Format validation failed; %s", err.Error())
		}
		return ok, ""
	} else if reqc.Kind == common.SignatureCustomResourceKind {
		ok, err := ValidateResourceSignature(reqc)
		if err != nil {
			return false, fmt.Sprintf("Format validation failed; %s", err.Error())
		}
		return ok, ""
	} else if reqc.Kind == common.ShieldConfigCustomResourceAPIVersion {
		ok, err := ValidateShieldConfig(reqc)
		if err != nil {
			return false, fmt.Sprintf("Format validation failed; %s", err.Error())
		}
		return ok, ""
	} else if reqc.Kind == common.SignerConfigCustomResourceKind {
		ok, err := ValidateSignerConfig(reqc)
		if err != nil {
			return false, fmt.Sprintf("Format validation failed; %s", err.Error())
		}
		return ok, ""
	} else if reqc.Kind == common.HelmReleaseMetadataCustomResourceAPIVersion {
		ok, err := ValidateHelmReleaseMetadata(reqc)
		if err != nil {
			return false, fmt.Sprintf("Format validation failed; %s", err.Error())
		}
		return ok, ""
	}
	return true, ""
}

func ValidateResourceSigningProfile(reqc *common.ReqContext, shieldNamespace string) (bool, error) {
	var data *rsp.ResourceSigningProfile
	dec := json.NewDecoder(bytes.NewReader(reqc.RawObject))
	dec.DisallowUnknownFields() // Force errors if data has undefined fields

	if err := dec.Decode(&data); err != nil {
		return false, err
	}
	if reqc.Namespace != shieldNamespace && data.Spec.TargetNamespaceSelector != nil {
		return false, fmt.Errorf("%s.Spec.TargetNamespaceSelector is allowed only for %s in %s.", common.ProfileCustomResourceKind, common.ProfileCustomResourceKind, shieldNamespace)
	}
	return true, nil
}

func ValidateResourceSignature(reqc *common.ReqContext) (bool, error) {
	var data *rsig.ResourceSignature
	dec := json.NewDecoder(bytes.NewReader(reqc.RawObject))
	dec.DisallowUnknownFields() // Force errors if data has undefined fields

	if err := dec.Decode(&data); err != nil {
		return false, err
	}
	if len(data.Spec.Data) > 1 {
		return false, fmt.Errorf("Only 1 signature data can be defined in 1 %s.", common.SignatureCustomResourceKind)
	}
	labels := data.GetLabels()
	missingLabels := []string{}
	if _, ok1 := labels[common.ResSigLabelApiVer]; !ok1 {
		missingLabels = append(missingLabels, "\""+common.ResSigLabelApiVer+"\"")
	}
	if _, ok2 := labels[common.ResSigLabelKind]; !ok2 {
		missingLabels = append(missingLabels, "\""+common.ResSigLabelKind+"\"")
	}
	if _, ok3 := labels[common.ResSigLabelTime]; !ok3 {
		missingLabels = append(missingLabels, "\""+common.ResSigLabelTime+"\"")
	}
	if len(missingLabels) > 0 {
		missingLabelStr := strings.Join(missingLabels, ", ")
		return false, fmt.Errorf("Required label %s is missing.", missingLabelStr)
	}
	return true, nil
}

func ValidateShieldConfig(reqc *common.ReqContext) (bool, error) {
	var data *sconf.ShieldConfig
	dec := json.NewDecoder(bytes.NewReader(reqc.RawObject))
	dec.DisallowUnknownFields() // Force errors if data has undefined fields

	if err := dec.Decode(&data); err != nil {
		return false, err
	}
	return true, nil
}

func ValidateSignerConfig(reqc *common.ReqContext) (bool, error) {
	var data *sigconf.SignerConfig
	dec := json.NewDecoder(bytes.NewReader(reqc.RawObject))
	dec.DisallowUnknownFields() // Force errors if data has undefined fields

	if err := dec.Decode(&data); err != nil {
		return false, err
	}
	if data.Spec.Config == nil {
		return false, fmt.Errorf("`spec.config` in SignerConfig is empty.")
	}
	if data.Spec.Config.Signers == nil || len(data.Spec.Config.Signers) == 0 {
		return false, fmt.Errorf("`spec.config.signers` in SignerConfig is empty.")
	}
	for i, signer := range data.Spec.Config.Signers {
		if signer.Subjects == nil || len(signer.Subjects) == 0 {
			return false, fmt.Errorf("`spec.config.signers[%s].subjects` in SignerConfig is empty.", strconv.Itoa(i))
		}
	}

	return true, nil
}

func ValidateHelmReleaseMetadata(reqc *common.ReqContext) (bool, error) {
	var data *hrm.HelmReleaseMetadata
	dec := json.NewDecoder(bytes.NewReader(reqc.RawObject))
	dec.DisallowUnknownFields() // Force errors if data has undefined fields

	if err := dec.Decode(&data); err != nil {
		return false, err
	}
	return true, nil
}
