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
	"os/exec"
	"time"

	"github.com/IBM/integrity-enforcer/shield/pkg/common/common"
	. "github.com/onsi/ginkgo" //nolint:golint
	. "github.com/onsi/gomega" //nolint:golint

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Test integrity shield", func() {
	Describe("Check operator status in ns:"+ishield_namespace, func() {
		It("Operator Pod should be Running Status", func() {
			framework := initFrameWork()
			var timeout int = 120
			expected := "integrity-shield-operator-controller-manager"
			Eventually(func() error {
				return CheckPodStatus(framework, ishield_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
		It("Operator sa should be created", func() {
			framework := initFrameWork()
			expected := ishield_op_sa
			err := CheckIShieldResources(framework, "ServiceAccount", ishield_namespace, expected)
			Expect(err).To(BeNil())
		})
		It("Operator role should be created", func() {
			framework := initFrameWork()
			expected := ishield_op_role
			err := CheckIShieldResources(framework, "Role", ishield_namespace, expected)
			Expect(err).To(BeNil())
		})
		It("Operator rb should be created", func() {
			framework := initFrameWork()
			expected := ishield_op_rb
			err := CheckIShieldResources(framework, "RoleBinding", ishield_namespace, expected)
			Expect(err).To(BeNil())
		})
	})

	Describe("Check ishield server in ns:"+ishield_namespace, func() {
		It("Server should be created properly", func() {
			framework := initFrameWork()
			var timeout int = 300
			expected := "integrity-shield-server"
			cmd_err := Kubectl("apply", "-f", integrityShieldOperatorCR, "-n", ishield_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckPodStatus(framework, ishield_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
	})

	Describe("Test ishield resources", func() {
		It("Iv resources should be created properly", func() {
			framework := initFrameWork()
			vc_name := "ishield-config"
			vc, err := framework.ShieldConfigClient.ShieldConfigs(ishield_namespace).Get(goctx.Background(), vc_name, metav1.GetOptions{})
			Expect(err).To(BeNil())
			ishield_resource_list := []*common.ResourceRef{}
			ishield_resource_list = append(ishield_resource_list, vc.Spec.ShieldConfig.IShieldResourceCondition.OperatorResources...)
			ishield_resource_list = append(ishield_resource_list, vc.Spec.ShieldConfig.IShieldResourceCondition.ServerResources...)
			By("Check created ishield resources...")
			for _, ishieldr := range ishield_resource_list {
				fmt.Print(ishieldr.Kind, " : ", ishieldr.Name, "\n")
				if ishieldr.Name == "" || ishieldr.Kind == "IntegrityShield" || ishieldr.Kind == "SecurityContextConstraints" || ishieldr.Kind == "PodSecurityPolicy" || ishieldr.Name == "helmreleasemetadatas.apis.integrityshield.io" {
					continue
				}
				err := CheckIShieldResources(framework, ishieldr.Kind, ishieldr.Namespace, ishieldr.Name)
				Expect(err).To(BeNil())
			}
		})
		It("Deleting ishield resources should be blocked", func() {
			if skip_default_user_test {
				Skip("This test should be done by default user")
			}
			time.Sleep(time.Second * 15)
			framework := initFrameWork()
			// change kube context
			err := ChangeKubeContextToDefaultUser(framework, test_namespace, "default-token-")
			Expect(err).To(BeNil())
			// load ishield resource lists
			vc_name := "ishield-config"
			vc, err := framework.ShieldConfigClient.ShieldConfigs(ishield_namespace).Get(goctx.Background(), vc_name, metav1.GetOptions{})
			Expect(err).To(BeNil())
			ishield_resource_list := []*common.ResourceRef{}
			ishield_resource_list = append(ishield_resource_list, vc.Spec.ShieldConfig.IShieldResourceCondition.OperatorResources...)
			ishield_resource_list = append(ishield_resource_list, vc.Spec.ShieldConfig.IShieldResourceCondition.ServerResources...)
			By("Try to Delete ishield resources...")
			for _, ishieldr := range ishield_resource_list {
				fmt.Print(ishieldr.Kind, " : ", ishieldr.Name, "\n")
				if ishieldr.Name == "" || ishieldr.Kind == "SecurityContextConstraints" || ishieldr.Kind == "PodSecurityPolicy" || ishieldr.Name == "helmreleasemetadatas.apis.integrityshield.io" {
					continue
				}
				if ishieldr.Namespace != "" {
					cmd_err := Kubectl("delete", ishieldr.Kind, ishieldr.Name, "-n", ishieldr.Namespace)
					Expect(cmd_err).NotTo(BeNil())
				} else {
					cmd_err := Kubectl("delete", ishieldr.Kind, ishieldr.Name)
					Expect(cmd_err).NotTo(BeNil())
				}
			}
			// change kube context
			err = ChangeKubeContextToKubeAdmin()
			Expect(err).To(BeNil())
		})
		It("IShield Resources are changed when IShield CR is updated", func() {
			if !local_test {
				Skip("This test is executed only in the local env.")
			}
			framework := initFrameWork()
			var timeout int = 120
			expected := DefaultSignPolicyCRName
			var generation int64
			sp, err := framework.SignPolicyClient.SignPolicies(ishield_namespace).Get(goctx.Background(), expected, metav1.GetOptions{})
			Expect(err).To(BeNil())
			generation = sp.Generation
			cmd_err := Kubectl("apply", "-f", integrityShieldOperatorCR_updated, "-n", ishield_namespace)
			Expect(cmd_err).To(BeNil())
			time.Sleep(time.Second * 15)
			Eventually(func() error {
				sp, err := framework.SignPolicyClient.SignPolicies(ishield_namespace).Get(goctx.Background(), expected, metav1.GetOptions{})
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

	Describe("Test integrity shield server", func() {
		Context("RSP in test ns is effective", func() {
			It("Resources should be unmonitored if rsp does not exist.", func() {
				framework := initFrameWork()
				var timeout int = 120
				expected := "unmonitored-configmap"
				server_name := "integrity-shield-server"
				cmd_err := Kubectl("create", "cm", expected, "-n", test_namespace)
				Expect(cmd_err).To(BeNil())
				server := GetPodName(framework, ishield_namespace, server_name)
				Eventually(func() error {
					cmdstr := "kubectl logs " + server + " -c server -n " + ishield_namespace + " | grep " + expected
					out, cmd_err := exec.Command("sh", "-c", cmdstr).Output()
					if cmd_err != nil {
						return cmd_err
					}
					if len(string(out)) != 0 {
						return nil
					}
					return fmt.Errorf("Fail to check unmonitored resource")
				}, timeout, 1).Should(BeNil())
				Eventually(func() error {
					return CheckConfigMap(framework, test_namespace, expected)
				}, timeout, 1).Should(BeNil())
			})
			It("RSP should be created properly", func() {
				framework := initFrameWork()
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
			It("Unsigned resouce should be blocked", func() {
				framework := initFrameWork()
				time.Sleep(time.Second * 30)
				var timeout int = 120
				expected := "test-configmap"
				cmd_err := Kubectl("apply", "-f", test_configmap, "-n", test_namespace)
				Expect(cmd_err).NotTo(BeNil())
				Eventually(func() error {
					return CheckEventNoSignature(framework, test_namespace, expected)
				}, timeout, 1).Should(BeNil())
			})
			It("Signed resouce should be allowed (ResourceSignature) ", func() {
				framework := initFrameWork()
				var timeout int = 120
				expected := "test-configmap"
				cmd_err := Kubectl("apply", "-f", test_configmap_rs, "-n", test_namespace)
				Expect(cmd_err).To(BeNil())
				cmd_err = Kubectl("apply", "-f", test_configmap, "-n", test_namespace)
				Expect(cmd_err).To(BeNil())
				Eventually(func() error {
					return CheckConfigMap(framework, test_namespace, expected)
				}, timeout, 1).Should(BeNil())
			})
			It("Signed resouce should be allowed (Annotation) ", func() {
				framework := initFrameWork()
				var timeout int = 120
				expected := "test-configmap2"
				cmd_err := Kubectl("apply", "-f", test_configmap2, "-n", test_namespace)
				Expect(cmd_err).To(BeNil())
				Eventually(func() error {
					return CheckConfigMap(framework, test_namespace, expected)
				}, timeout, 1).Should(BeNil())
			})
			It("Changing whitelisted part should be allowed", func() {
				framework := initFrameWork()
				var timeout int = 120
				expected := "test-configmap"
				server_name := "integrity-shield-server"
				server := GetPodName(framework, ishield_namespace, server_name)
				// apply cm
				cmd_err := Kubectl("apply", "-f", test_configmap_updated, "-n", test_namespace)
				Expect(cmd_err).To(BeNil())
				Eventually(func() error {
					// check forwarder log
					cmdstr := "kubectl logs " + server + " -c forwarder -n " + ishield_namespace + " | grep " + expected + " | grep no-mutation | grep UPDATE"
					out, cmd_err := exec.Command("sh", "-c", cmdstr).Output()
					if cmd_err != nil {
						return cmd_err
					}
					if len(string(out)) == 0 {
						return fmt.Errorf("Fail to find expected forwarder log")
					}
					return nil
				}, timeout, 1).Should(BeNil())
			})
			It("Request is allowed if filtered by IgnoredKind", func() {
			})
			It("Request is allowed if filtered by IgnoredSA", func() {
			})
			It("Request is allowed if error occured", func() {
			})
			It("Unsigned resource can be created if filtered by exclude rule", func() {
				framework := initFrameWork()
				var timeout int = 120
				expected := "test-configmap3"
				cmd_err := Kubectl("create", "cm", expected, "-n", test_namespace)
				Expect(cmd_err).To(BeNil())
				Eventually(func() error {
					return CheckConfigMap(framework, test_namespace, expected)
				}, timeout, 1).Should(BeNil())
			})
			It("RSP should be deleted properly", func() {
				if !local_test {
					Skip("This test is executed only in the local env.")
				}
				framework := initFrameWork()
				var timeout int = 120
				expected := "test-rsp"
				cmd_err := Kubectl("delete", "-f", test_rsp, "-n", test_namespace)
				Expect(cmd_err).To(BeNil())
				Eventually(func() error {
					_, err := framework.RSPClient.ResourceSigningProfiles(test_namespace).Get(goctx.Background(), expected, metav1.GetOptions{})
					return err
				}, timeout, 1).ShouldNot(BeNil())
			})
			It("Unsigned resouce should not be blocked", func() {
				if !local_test {
					Skip("This test is executed only in the local env.")
				}
				framework := initFrameWork()
				var timeout int = 120
				time.Sleep(time.Second * 30)
				expected := "test-configmap4"
				cmd_err := Kubectl("create", "cm", expected, "-n", test_namespace)
				Expect(cmd_err).To(BeNil())
				Eventually(func() error {
					return CheckConfigMap(framework, test_namespace, expected)
				}, timeout, 1).Should(BeNil())
			})
		})
		Context("RSP in IShield NS is effective on newly created NS", func() {
			It("Delete test namespace", func() {
				cmd_err := Kubectl("get", "ns", test_namespace)
				if cmd_err == nil {
					test_rsp_name := "test-rsp"
					err := Kubectl("get", "rsp", test_rsp_name, "-n", test_namespace)
					if err == nil {
						err := Kubectl("delete", "-f", test_rsp, "-n", test_namespace)
						Expect(err).To(BeNil())
					}
					err = Kubectl("delete", "ns", test_namespace)
					Expect(err).To(BeNil())
				}
				cmd_err = Kubectl("get", "ns", test_namespace)
				Expect(cmd_err).NotTo(BeNil())
			})
			It("RSP should be created properly", func() {
				framework := initFrameWork()
				var timeout int = 120
				expected := "test-rsp"
				By("Creating test rsp: " + test_rsp_ishield + " ns: " + ishield_namespace)
				cmd_err := Kubectl("apply", "-f", test_rsp_ishield, "-n", ishield_namespace)
				Expect(cmd_err).To(BeNil())
				By("Checking rsp is created properly: " + test_rsp_ishield + " ns: " + ishield_namespace)
				Eventually(func() error {
					_, err := framework.RSPClient.ResourceSigningProfiles(ishield_namespace).Get(goctx.Background(), expected, metav1.GetOptions{})
					if err != nil {
						return err
					}
					return nil
				}, timeout, 1).Should(BeNil())
			})
			It("Unsigned resource should be blocked in new namespace", func() {
				framework := initFrameWork()
				var timeout int = 120
				expected := "test-configmap"
				By("Creating new namespace: " + test_namespace)
				cmd_err := Kubectl("create", "ns", test_namespace)
				Expect(cmd_err).To(BeNil())
				By("Creating test configmap in ns: " + test_namespace)
				cmd_err = Kubectl("apply", "-f", test_configmap, "-n", test_namespace)
				Expect(cmd_err).NotTo(BeNil())
				Eventually(func() error {
					return CheckEventNoSignature(framework, test_namespace, expected)
				}, timeout, 1).Should(BeNil())
			})
			It("Signed resource should be allowed in new namespace", func() {
				framework := initFrameWork()
				var timeout int = 120
				expected := "test-configmap2"
				By("Creating test configmap in ns: " + test_namespace)
				cmd_err := Kubectl("apply", "-f", test_configmap2, "-n", test_namespace)
				Expect(cmd_err).To(BeNil())
				Eventually(func() error {
					return CheckConfigMap(framework, test_namespace, expected)
				}, timeout, 1).Should(BeNil())
			})
		})
	})

	Describe("Test integrity shield resources: delete", func() {
		It("Server and ishield resources should be deleted properly", func() {
			if !local_test {
				Skip("This test is executed only in the local env.")
			}
			framework := initFrameWork()
			vc_name := "ishield-config"
			By("Load ishield resource list")
			vc, err := framework.ShieldConfigClient.ShieldConfigs(ishield_namespace).Get(goctx.Background(), vc_name, metav1.GetOptions{})
			Expect(err).To(BeNil())
			ishield_resource_list := []*common.ResourceRef{}
			ishield_resource_list = append(ishield_resource_list, vc.Spec.ShieldConfig.IShieldResourceCondition.OperatorResources...)
			ishield_resource_list = append(ishield_resource_list, vc.Spec.ShieldConfig.IShieldResourceCondition.ServerResources...)
			By("Server should be deleted properly")
			var timeout int = 300
			expected := "integrity-shield-server"
			cmd_err := Kubectl("delete", "-f", integrityShieldOperatorCR, "-n", ishield_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckPodStatus(framework, ishield_namespace, expected)
			}, timeout, 1).ShouldNot(BeNil())
			By("Iv resources should be deleted properly")
			time.Sleep(time.Second * 30)
			for _, ishieldr := range ishield_resource_list {
				fmt.Print(ishieldr.Kind, " : ", ishieldr.Name, "\n")
				if ishieldr.Name == "" || ishieldr.Kind == "IntegrityShield" || ishieldr.Kind == "SecurityContextConstraints" || ishieldr.Kind == "PodSecurityPolicy" || ishieldr.Name == "integrity-shield-operator-controller-manager" || ishieldr.Name == "helmreleasemetadatas.apis.integrityshield.io" || ishieldr.Name == "integrityshields.apis.integrityshield.io" {
					continue
				}
				err := CheckIShieldResources(framework, ishieldr.Kind, ishieldr.Namespace, ishieldr.Name)
				Expect(err).NotTo(BeNil())
			}
		})
	})
})
