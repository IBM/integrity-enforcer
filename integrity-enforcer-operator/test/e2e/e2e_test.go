// Copyright 2020 The Operator-SDK Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package e2e

import (
	goctx "context"
	"fmt"
	"time"

	// "testing"

	. "github.com/onsi/ginkgo" //nolint:golint
	. "github.com/onsi/gomega" //nolint:golint

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Test integrity enforcer handling", func() {
	Describe("Check operator status in ns:"+ie_namespace, func() {
		It("should be Running Status", func() {
			var timeout int = 120
			expected := "integrity-enforcer-operator-controller-manager"
			framework := initFrameWork()
			Eventually(func() error {
				return CheckPodStatus(framework, ie_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
	})
	Describe("Install ie server in ns:"+ie_namespace, func() {
		It("should be created properly", func() {
			By("Creating cr: " + integrityEnforcerOperatorCR)
			var timeout int = 300
			expected := "integrity-enforcer-server"
			framework := initFrameWork()
			cmd_err := Kubectl("apply", "-f", integrityEnforcerOperatorCR, "-n", ie_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckPodStatus(framework, ie_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
	})
	Describe("Check integrity enforcer resource CRDs", func() {
		framework := initFrameWork()
		It("EnforcerConfig should be created properly", func() {
			expected := "enforcerconfigs.apis.integrityenforcer.io"
			_, err := framework.APIExtensionsClientSet.ApiextensionsV1().CustomResourceDefinitions().Get(goctx.Background(), expected, metav1.GetOptions{})
			Expect(err).To(BeNil())
		})
		It("ResourceSignature should be created properly", func() {
			expected := "resourcesignatures.apis.integrityenforcer.io"
			_, err := framework.APIExtensionsClientSet.ApiextensionsV1().CustomResourceDefinitions().Get(goctx.Background(), expected, metav1.GetOptions{})
			Expect(err).To(BeNil())
		})
		It("ResourceSigningProfile should be created properly", func() {
			expected := "resourcesigningprofiles.apis.integrityenforcer.io"
			_, err := framework.APIExtensionsClientSet.ApiextensionsV1().CustomResourceDefinitions().Get(goctx.Background(), expected, metav1.GetOptions{})
			Expect(err).To(BeNil())
		})
		It("SignPolicy should be created properly", func() {
			expected := "signpolicies.apis.integrityenforcer.io"
			_, err := framework.APIExtensionsClientSet.ApiextensionsV1().CustomResourceDefinitions().Get(goctx.Background(), expected, metav1.GetOptions{})
			Expect(err).To(BeNil())
		})
	})

	var _ = Describe("Test integrity enforcer function", func() {
		framework := initFrameWork()
		It("Test RSP should be created properly", func() {
			var timeout int = 120
			expected := "test-rsp"
			By("Creating test rsp: " + test_rsp + " ns: " + test_namespace)
			cmd_err := Kubectl("apply", "-f", test_rsp, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				_, err := framework.RSPClient.ResourceSigningProfiles(test_namespace).Get(goctx.Background(), expected, metav1.GetOptions{})
				if err != nil {
					return err
				}
				return nil
			}, timeout, 1).Should(BeNil())
		})
		It("Test unsigned resouce should be blocked", func() {
			time.Sleep(time.Second * 30)
			var timeout int = 60
			expected := "test-configmap"
			By("Creating test configmap in ns: " + test_namespace + " : " + test_configmap)
			cmd_err := Kubectl("apply", "-f", test_configmap, "-n", test_namespace)
			Expect(cmd_err).NotTo(BeNil())
			Eventually(func() error {
				return CheckEventNoSignature(framework, test_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
		It("Test (ResourceSignature) signed resouce should be allowed", func() {
			var timeout int = 60
			expected := "test-configmap"
			By("Creating resource signature in ns: " + test_namespace)
			cmd_err := Kubectl("apply", "-f", test_configmap_rs, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			By("Creating test configmap in ns: " + test_namespace)
			cmd_err = Kubectl("apply", "-f", test_configmap, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckConfigMap(framework, test_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
		It("Test (Annotation) signed resouce should be allowed", func() {
			var timeout int = 60
			expected := "test-configmap2"
			By("Creating test configmap in ns: " + test_namespace)
			cmd_err := Kubectl("apply", "-f", test_configmap2, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckConfigMap(framework, test_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
	})
	Describe("Test IE resources", func() {
		framework := initFrameWork()
		It("No changed on IE resources allowed", func() {
		})
		It("IE Resources are changed when IE CR is updated", func() {
			var timeout int = 60
			expected := "sign-policy"
			var generation int64
			sp, err := framework.SignPolicyClient.SignPolicies(ie_namespace).Get(goctx.Background(), expected, metav1.GetOptions{})
			Expect(err).To(BeNil())
			generation = sp.Generation
			By("Applying updated CR: " + ie_namespace)
			cmd_err := Kubectl("apply", "-f", integrityEnforcerOperatorCR_updated, "-n", ie_namespace)
			Expect(cmd_err).To(BeNil())
			time.Sleep(time.Second * 15)
			Eventually(func() error {
				sp, err := framework.SignPolicyClient.SignPolicies(ie_namespace).Get(goctx.Background(), expected, metav1.GetOptions{})
				if err != nil {
					return err
				}
				if sp.Generation == generation {
					return fmt.Errorf("SignPolicy is not changed: %v", expected)
				}
				return nil
			}, timeout, 1).Should(BeNil())
		})
		// Context("RSP in IE NS is effective for blocking unsigned admission on newly created NS", func() {
		// 	It("Test RSP should be created properly", func() {
		// 		var timeout int = 60
		// 		expected := "test-rsp"
		// 		By("Creating test rsp: " + test_rsp + " ns: " + ie_namespace)
		// 		cmd_err := Kubectl("apply", "-f", test_rsp, "-n", ie_namespace)
		// 		Expect(cmd_err).To(BeNil())
		// 		Eventually(func() error {
		// 			_, err := framework.RSPClient.ResourceSigningProfiles(ie_namespace).Get(goctx.Background(), expected, metav1.GetOptions{})
		// 			if err != nil {
		// 				return err
		// 			}
		// 			return nil
		// 		}, timeout, 1).Should(BeNil())
		// 	})
		// 	It("Test unsigned resource should be blocked in new namespace", func() {
		// 		time.Sleep(time.Second * 15)
		// 		var timeout int = 60
		// 		expected := "test-configmap"
		// 		By("Creating new namespace: " + test_namespace2)
		// 		cmd_err := Kubectl("create", "ns", test_namespace2)
		// 		Expect(cmd_err).To(BeNil())
		// 		By("Creating test configmap in ns: " + test_namespace2)
		// 		cmd_err = Kubectl("apply", "-f", test_configmap, "-n", test_namespace2)
		// 		Expect(cmd_err).NotTo(BeNil())
		// 		Eventually(func() error {
		// 			return CheckEventNoSignature(framework, test_namespace, expected)
		// 		}, timeout, 1).Should(BeNil())
		// 	})
		// 	It("Test signed resource should be allowed in new namespace", func() {
		// 		var timeout int = 60
		// 		expected := "test-configmap2"
		// 		By("Creating test configmap in ns: " + test_namespace2)
		// 		cmd_err := Kubectl("apply", "-f", test_configmap2, "-n", test_namespace2)
		// 		Expect(cmd_err).To(BeNil())
		// 		Eventually(func() error {
		// 			return CheckConfigMap(framework, test_namespace2, expected)
		// 		}, timeout, 1).Should(BeNil())
		// 	})
		// })
	})
})
