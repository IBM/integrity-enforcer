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

package observer

import (
	"fmt"
	"os"
	"strings"
	"time"

	k8smnfconfig "github.com/IBM/integrity-shield/integrity-shield-server/pkg/config"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func ObserveResources(resources []unstructured.Unstructured, signatureRef k8smnfconfig.SignatureRef, ignoreFields k8smanifest.ObjectFieldBindingList, secrets []k8smnfconfig.KeyConfig) []VerifyResultDetail {
	results := []VerifyResultDetail{}
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		namespace = defaultPodNamespace
	}
	for _, resource := range resources {
		log.Debug("Observed Resource:", resource.GetAPIVersion(), resource.GetKind(), resource.GetNamespace(), resource.GetName())
		vo := &k8smanifest.VerifyResourceOption{}
		vo.IgnoreFields = ignoreFields
		// vo.CheckDryRunForApply = true
		// vo.Provenance = true
		vo.DryRunNamespace = namespace

		if signatureRef.ImageRef != "" {
			vo.ImageRef = signatureRef.ImageRef
		}
		if signatureRef.SignatureResourceRef.Name != "" && signatureRef.SignatureResourceRef.Namespace != "" {
			ref := fmt.Sprintf("k8s://ConfigMap/%s/%s", signatureRef.SignatureResourceRef.Namespace, signatureRef.SignatureResourceRef.Name)
			vo.SignatureResourceRef = ref
		}
		if signatureRef.ProvenanceResourceRef.Name != "" && signatureRef.ProvenanceResourceRef.Namespace != "" {
			ref := fmt.Sprintf("k8s://ConfigMap/%s/%s", signatureRef.ProvenanceResourceRef.Namespace, signatureRef.ProvenanceResourceRef.Name)
			vo.ProvenanceResourceRef = ref
		}
		// secret
		for _, s := range secrets {
			if s.KeySecretNamespace == resource.GetNamespace() {
				pubkey, err := LoadKeySecret(s.KeySecretNamespace, s.KeySecretName)
				if err != nil {
					fmt.Println("Failed to load pubkey; err: ", err.Error())
				}
				vo.KeyPath = pubkey
				break
			}
		}
		log.Debug("VerifyResourceOption", vo)
		result, err := k8smanifest.VerifyResource(resource, vo)
		log.Debug("VerifyResource result: ", result)
		if err != nil {
			log.Warning("Signature verification is required for this request, but verifyResource return error ; %s", err.Error())
			results = append(results, VerifyResultDetail{
				Time:                 time.Now().Format(timeFormat),
				Kind:                 resource.GroupVersionKind().Kind,
				ApiGroup:             resource.GetObjectKind().GroupVersionKind().Group,
				ApiVersion:           resource.GetObjectKind().GroupVersionKind().Version,
				Name:                 resource.GetName(),
				Namespace:            resource.GetNamespace(),
				Error:                true,
				Message:              err.Error(),
				Violation:            true,
				VerifyResourceResult: nil,
			})
			continue
		}
		message := ""
		if result.InScope {
			if result.Verified {
				message = fmt.Sprintf("singed by a valid signer: %s", result.Signer)
			} else {
				message = "no signature found"
				if result.Diff != nil && result.Diff.Size() > 0 {
					message = fmt.Sprintf("diff found: %s", result.Diff.String())
				} else if result.Signer != "" {
					message = fmt.Sprintf("signer config not matched, this is signed by %s", result.Signer)
				}
			}
		} else {
			message = "not protected"
		}
		tmpMsg := strings.Split(message, " (Request: {")
		resultMsg := ""
		if len(tmpMsg) > 0 {
			resultMsg = tmpMsg[0]
		}

		violation := true
		if result.Verified {
			violation = false
		}
		results = append(results, VerifyResultDetail{
			Time: time.Now().Format(timeFormat),
			// Resource:             resource,
			Kind:                 resource.GroupVersionKind().Kind,
			Name:                 resource.GetName(),
			Namespace:            resource.GetNamespace(),
			Error:                false,
			Message:              resultMsg,
			VerifyResourceResult: result,
			Violation:            violation,
		})
	}
	return results
}
