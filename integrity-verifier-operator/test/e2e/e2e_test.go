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

	. "github.com/onsi/ginkgo" //nolint:golint
	. "github.com/onsi/gomega" //nolint:golint

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Test integrity verifier", func() {
	Describe("Check operator status in ns:"+iv_namespace, func() {
		framework := initFrameWork()
		It("Operator Pod should be Running Status", func() {
			var timeout int = 120
			expected := "integrity-verifier-operator-controller-manager"
			Eventually(func() error {
				return CheckPodStatus(framework, iv_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
		It("Operator sa should be created", func() {
			expected := iv_op_sa
			err := CheckIVResources(framework, "ServiceAccount", iv_namespace, expected)
			Expect(err).To(BeNil())
		})
		It("Operator role should be created", func() {
			expected := iv_op_role
			err := CheckIVResources(framework, "Role", iv_namespace, expected)
			Expect(err).To(BeNil())
		})
		It("Operator rb should be created", func() {
			expected := iv_op_rb
			err := CheckIVResources(framework, "RoleBinding", iv_namespace, expected)
			Expect(err).To(BeNil())
		})
	})

	Describe("Check iv server in ns:"+iv_namespace, func() {
		framework := initFrameWork()
		It("Server should be created properly", func() {
			var timeout int = 300
			expected := "integrity-verifier-server"
			cmd_err := Kubectl("apply", "-f", integrityVerifierOperatorCR, "-n", iv_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckPodStatus(framework, iv_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
	})

	Describe("Test iv resources", func() {
		// defer GinkgoRecover()
		framework := initFrameWork()
		It("Iv resources should be created properly", func() {
			vc_name := "iv-config"
			vc, err := framework.VerifierConfigClient.VerifierConfigs(iv_namespace).Get(goctx.Background(), vc_name, metav1.GetOptions{})
			Expect(err).To(BeNil())
			iv_resource_list := vc.Spec.VerifierConfig.IVResourceCondition.References
			fmt.Print("Check created iv resources... \n")
			for _, ivr := range iv_resource_list {
				fmt.Print(ivr.Kind, " : ", ivr.Name, "\n")
				if ivr.Name == "" || ivr.Kind == "IntegrityVerifier" || ivr.Kind == "SecurityContextConstraints" || ivr.Kind == "PodSecurityPolicy" || ivr.Name == "helmreleasemetadatas.apis.integrityverifier.io" {
					continue
				}
				err := CheckIVResources(framework, ivr.Kind, ivr.Namespace, ivr.Name)
				Expect(err).To(BeNil())
			}
		})
		It("Deleting iv resources should be blocked", func() {
			vc_name := "iv-config"
			vc, err := framework.VerifierConfigClient.VerifierConfigs(iv_namespace).Get(goctx.Background(), vc_name, metav1.GetOptions{})
			Expect(err).To(BeNil())
			iv_resource_list := vc.Spec.VerifierConfig.IVResourceCondition.References
			fmt.Print("Try to Delete iv resources... \n")
			for _, ivr := range iv_resource_list {
				fmt.Print(ivr.Kind, " : ", ivr.Name, "\n")
				if ivr.Name == "" || ivr.Kind == "SecurityContextConstraints" || ivr.Kind == "PodSecurityPolicy" || ivr.Name == "helmreleasemetadatas.apis.integrityverifier.io" {
					continue
				}
				if ivr.Namespace != "" {
					cmd_err := Kubectl("delete", ivr.Kind, ivr.Name, "-n", ivr.Namespace)
					Expect(cmd_err).NotTo(BeNil())
				} else {
					cmd_err := Kubectl("delete", ivr.Kind, ivr.Name)
					Expect(cmd_err).NotTo(BeNil())
				}
			}
		})
		It("IV Resources are changed when IV CR is updated", func() {
			var timeout int = 60
			expected := DefaultSignPolicyCRName
			var generation int64
			sp, err := framework.SignPolicyClient.SignPolicies(iv_namespace).Get(goctx.Background(), expected, metav1.GetOptions{})
			Expect(err).To(BeNil())
			generation = sp.Generation
			cmd_err := Kubectl("apply", "-f", integrityVerifierOperatorCR_updated, "-n", iv_namespace)
			Expect(cmd_err).To(BeNil())
			time.Sleep(time.Second * 15)
			Eventually(func() error {
				sp, err := framework.SignPolicyClient.SignPolicies(iv_namespace).Get(goctx.Background(), expected, metav1.GetOptions{})
				if err != nil {
					return err
				}
				if sp.Generation == generation {
					return fmt.Errorf("SignPolicy is not changed: %v", expected)
				}
				return nil
			}, timeout, 1).Should(BeNil())
		})
	})

	Describe("Test integrity verifier server", func() {
		framework := initFrameWork()
		Context("Test integrity verifier function", func() {
			It("Test RSP should be created properly", func() {
				var timeout int = 120
				expected := "test-rsp"
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
				cmd_err := Kubectl("apply", "-f", test_configmap, "-n", test_namespace)
				Expect(cmd_err).NotTo(BeNil())
				Eventually(func() error {
					return CheckEventNoSignature(framework, test_namespace, expected)
				}, timeout, 1).Should(BeNil())
			})
			It("Test (ResourceSignature) signed resouce should be allowed", func() {
				var timeout int = 60
				expected := "test-configmap"
				cmd_err := Kubectl("apply", "-f", test_configmap_rs, "-n", test_namespace)
				Expect(cmd_err).To(BeNil())
				cmd_err = Kubectl("apply", "-f", test_configmap, "-n", test_namespace)
				Expect(cmd_err).To(BeNil())
				Eventually(func() error {
					return CheckConfigMap(framework, test_namespace, expected)
				}, timeout, 1).Should(BeNil())
			})
			It("Test (Annotation) signed resouce should be allowed", func() {
				var timeout int = 60
				expected := "test-configmap2"
				cmd_err := Kubectl("apply", "-f", test_configmap2, "-n", test_namespace)
				Expect(cmd_err).To(BeNil())
				Eventually(func() error {
					return CheckConfigMap(framework, test_namespace, expected)
				}, timeout, 1).Should(BeNil())
			})
		})
		// Context("RSP in IV NS is effective for blocking unsigned admission on newly created NS", func() {
		// 	It("Test RSP should be created properly", func() {
		// 		var timeout int = 60
		// 		expected := "test-rsp"
		// 		By("Creating test rsp: " + test_rsp + " ns: " + iv_namespace)
		// 		cmd_err := Kubectl("apply", "-f", test_rsp, "-n", iv_namespace)
		// 		Expect(cmd_err).To(BeNil())
		// 		Eventually(func() error {
		// 			_, err := framework.RSPClient.ResourceSigningProfiles(iv_namespace).Get(goctx.Background(), expected, metav1.GetOptions{})
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

	Describe("Test integrity verifier resources: delete", func() {
		framework := initFrameWork()
		It("Server and iv resources should be deleted properly", func() {
			vc_name := "iv-config"
			By("Load iv resource list")
			vc, err := framework.VerifierConfigClient.VerifierConfigs(iv_namespace).Get(goctx.Background(), vc_name, metav1.GetOptions{})
			Expect(err).To(BeNil())
			iv_resource_list := vc.Spec.VerifierConfig.IVResourceCondition.References
			By("Server should be deleted properly")
			var timeout int = 600
			expected := "integrity-verifier-server"
			cmd_err := Kubectl("delete", "-f", integrityVerifierOperatorCR, "-n", iv_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckPodStatus(framework, iv_namespace, expected)
			}, timeout, 1).ShouldNot(BeNil())
			By("Iv resources should be deleted properly")
			for _, ivr := range iv_resource_list {
				fmt.Print(ivr.Kind, " : ", ivr.Name, "\n")
				if ivr.Name == "" || ivr.Kind == "IntegrityVerifier" || ivr.Kind == "SecurityContextConstraints" || ivr.Kind == "PodSecurityPolicy" || ivr.Name == "integrity-verifier-operator-controller-manager" || ivr.Name == "helmreleasemetadatas.apis.integrityverifier.io" {
					continue
				}
				err := CheckIVResources(framework, ivr.Kind, ivr.Namespace, ivr.Name)
				Expect(err).NotTo(BeNil())
			}
		})
	})
})
