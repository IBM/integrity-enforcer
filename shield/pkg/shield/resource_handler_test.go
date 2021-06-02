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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	admv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	common "github.com/IBM/integrity-enforcer/shield/pkg/common"
	config "github.com/IBM/integrity-enforcer/shield/pkg/config"
	// +kubebuilder:scaffold:imports
)

func adReqToResource(adreq *admv1.AdmissionRequest) *unstructured.Unstructured {
	var obj *unstructured.Unstructured
	_ = json.Unmarshal(adreq.Object.Raw, &obj)
	return obj
}

func resourceHandlerTest() {
	It("Resource Handler Run Test (deny, secret-setup-error)", func() {
		var timeout int = 10
		Eventually(func() error {
			changedReq := getChangedRequest(req)
			res := adReqToResource(changedReq)
			var test2Config *config.ShieldConfig
			tmp, _ := json.Marshal(testConfig)
			_ = json.Unmarshal(tmp, &test2Config)
			test2Config.KeyPathList = []string{"./testdata/sample-signer-keyconfig/keyring-secret/pgp/miss-configured-pubring"}
			matchedProfiles, _ := GetMatchedProfilesWithResource(res, test2Config.Namespace)
			multipleResults := []*common.DecisionResult{}
			for _, profile := range matchedProfiles {
				metaLogger := getTestLogger(changedReq, test2Config)
				testHandler := NewResourceCheckHandler(test2Config, metaLogger, profile.Spec.Parameters)
				//process request
				result := testHandler.Run(res)
				multipleResults = append(multipleResults, result)
			}
			dr, _ := SummarizeMultipleDecisionResults(multipleResults)
			drBytes, _ := json.Marshal(dr)
			fmt.Printf("[TestInfo] drBytes: %s", string(drBytes))
			if dr == nil {
				return fmt.Errorf("Run() returns nil as AdmissionResponse")
			} else if !strings.Contains(dr.Message, "no verification keys are correctly loaded") {
				return fmt.Errorf("Run() returns wrong AdmissionResponse; Received Response: %s", dr.Message)
			}
			return nil
		}, timeout, 5).Should(BeNil())
	})
	It("Resource Handler Run Test (deny, signature-not-identical)", func() {
		var timeout int = 10
		Eventually(func() error {
			changedReq := getChangedRequest(req)
			res := adReqToResource(changedReq)
			matchedProfiles, _ := GetMatchedProfilesWithResource(res, testConfig.Namespace)
			multipleResults := []*common.DecisionResult{}
			for _, profile := range matchedProfiles {
				metaLogger := getTestLogger(changedReq, testConfig)
				testHandler := NewResourceCheckHandler(testConfig, metaLogger, profile.Spec.Parameters)
				//process request
				result := testHandler.Run(res)
				multipleResults = append(multipleResults, result)
			}
			dr, _ := SummarizeMultipleDecisionResults(multipleResults)
			drBytes, _ := json.Marshal(dr)
			fmt.Printf("[TestInfo] drBytes: %s", string(drBytes))
			if dr == nil {
				return fmt.Errorf("Run() returns nil as AdmissionResponse")
			} else if !strings.Contains(dr.Message, "not identical") {
				return fmt.Errorf("Run() returns wrong AdmissionResponse; Received Response: %s", dr.Message)
			}
			return nil
		}, timeout, 1).Should(BeNil())
	})
	It("Resource Handler Run Test (allow, valid signer, ResSig)", func() {
		var timeout int = 10
		Eventually(func() error {
			modReq := getRequestWithoutAnnoSig(req)
			res := adReqToResource(modReq)
			matchedProfiles, _ := GetMatchedProfilesWithResource(res, testConfig.Namespace)
			multipleResults := []*common.DecisionResult{}
			for _, profile := range matchedProfiles {
				metaLogger := getTestLogger(modReq, testConfig)
				testHandler := NewResourceCheckHandler(testConfig, metaLogger, profile.Spec.Parameters)
				//process request
				result := testHandler.Run(res)
				multipleResults = append(multipleResults, result)
			}
			dr, _ := SummarizeMultipleDecisionResults(multipleResults)

			drBytes, _ := json.Marshal(dr)
			fmt.Printf("[TestInfo] drBytes: %s", string(drBytes))
			if dr == nil {
				return fmt.Errorf("Run() returns nil as AdmissionResponse")
			} else if !strings.Contains(dr.Message, "valid signer") {
				return fmt.Errorf("Run() returns wrong AdmissionResponse; Received Response: %s", dr.Message)
			}
			return nil
		}, timeout, 1).Should(BeNil())
	})
	It("Resource Handler Run Test (allow, valid signer, updating a verified resource with new sig)", func() {
		var timeout int = 10
		Eventually(func() error {
			updReq := getUpdateRequest()
			res := adReqToResource(updReq)
			matchedProfiles, _ := GetMatchedProfilesWithResource(res, testConfig.Namespace)
			multipleResults := []*common.DecisionResult{}
			for _, profile := range matchedProfiles {
				metaLogger := getTestLogger(updReq, testConfig)
				testHandler := NewResourceCheckHandler(testConfig, metaLogger, profile.Spec.Parameters)
				//process request
				result := testHandler.Run(res)
				multipleResults = append(multipleResults, result)
			}
			dr, _ := SummarizeMultipleDecisionResults(multipleResults)

			drBytes, _ := json.Marshal(dr)
			fmt.Printf("[TestInfo] drBytes: %s", string(drBytes))
			if dr == nil {
				return fmt.Errorf("Run() returns nil as AdmissionResponse")
			} else if !strings.Contains(dr.Message, "valid signer") {
				return fmt.Errorf("Run() returns wrong AdmissionResponse; Received Response: %s", dr.Message)
			}
			return nil
		}, timeout, 1).Should(BeNil())
	})
	It("Resource Handler Run Test (allow, valid signer, updating a verified resource with only metadata change)", func() {
		var timeout int = 10
		Eventually(func() error {
			updReq := getUpdateWithMetaChangeRequest()
			res := adReqToResource(updReq)
			matchedProfiles, _ := GetMatchedProfilesWithResource(res, testConfig.Namespace)
			multipleResults := []*common.DecisionResult{}
			for _, profile := range matchedProfiles {
				metaLogger := getTestLogger(updReq, testConfig)
				testHandler := NewResourceCheckHandler(testConfig, metaLogger, profile.Spec.Parameters)
				//process request
				result := testHandler.Run(res)
				multipleResults = append(multipleResults, result)
			}
			dr, _ := SummarizeMultipleDecisionResults(multipleResults)

			drBytes, _ := json.Marshal(dr)
			fmt.Printf("[TestInfo] drBytes: %s", string(drBytes))
			if dr == nil {
				return fmt.Errorf("Run() returns nil as AdmissionResponse")
			} else if !strings.Contains(dr.Message, "valid signer") {
				return fmt.Errorf("Run() returns wrong AdmissionResponse; Received Response: %s", dr.Message)
			}
			return nil
		}, timeout, 1).Should(BeNil())
	})
	It("Resource Handler Run Test (allow, valid signer, creating CRD with annotation signature)", func() {
		var timeout int = 10
		Eventually(func() error {
			crdReq, crdTestConfig := getCRDRequest()
			res := adReqToResource(crdReq)
			matchedProfiles, _ := GetMatchedProfilesWithResource(res, crdTestConfig.Namespace)
			multipleResults := []*common.DecisionResult{}
			for _, profile := range matchedProfiles {
				metaLogger := getTestLogger(crdReq, crdTestConfig)
				testHandler := NewResourceCheckHandler(crdTestConfig, metaLogger, profile.Spec.Parameters)
				//process request
				result := testHandler.Run(res)
				multipleResults = append(multipleResults, result)
			}
			dr, _ := SummarizeMultipleDecisionResults(multipleResults)
			drBytes, _ := json.Marshal(dr)
			fmt.Printf("[TestInfo] drBytes: %s", string(drBytes))
			if dr == nil {
				return fmt.Errorf("Run() returns nil as AdmissionResponse")
			} else if !strings.Contains(dr.Message, "valid signer") {
				return fmt.Errorf("Run() returns wrong AdmissionResponse; Received Response: %s", dr.Message)
			}
			return nil
		}, timeout, 1).Should(BeNil())
	})
}
