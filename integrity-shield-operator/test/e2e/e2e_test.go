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
	"io/ioutil"
	"os/exec"
	"time"

	"github.com/IBM/integrity-enforcer/shield/pkg/common"
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
	})

	Describe("Check ishield server in ns:"+ishield_namespace, func() {
		It("Server should be created properly", func() {
			framework := initFrameWork()
			var timeout int = 300
			expected := "integrity-shield-server"
			cmd_err := Kubectl("apply", "-f", integrityShieldOperatorCR, "-n", ishield_namespace)
			if cmd_err != nil {
				fmt.Printf("Error while creating CR; %s\n", cmd_err.Error())
				if exitError, ok := cmd_err.(*exec.ExitError); ok {
					fmt.Printf("stderr: %s\n", string(exitError.Stderr))
				}
			}
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				return CheckPodStatus(framework, ishield_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
	})

	Describe("Test ishield resources", func() {
		It("IShield resources should be created properly", func() {
			framework := initFrameWork()
			isc_name := "ishield-config"
			isc, err := framework.ShieldConfigClient.ShieldConfigs(ishield_namespace).Get(goctx.Background(), isc_name, metav1.GetOptions{})
			Expect(err).To(BeNil())
			ishield_resource_list := []*common.ResourceRef{}
			ishield_resource_list = append(ishield_resource_list, isc.Spec.ShieldConfig.IShieldResourceCondition.OperatorResources...)
			ishield_resource_list = append(ishield_resource_list, isc.Spec.ShieldConfig.IShieldResourceCondition.ServerResources...)
			By("Check created ishield resources...")
			for _, iShieldRes := range ishield_resource_list {
				fmt.Print(iShieldRes.Kind, " : ", iShieldRes.Name, "\n")
				if iShieldRes.Name == "" || iShieldRes.Kind == "IntegrityShield" || iShieldRes.Kind == "SecurityContextConstraints" || iShieldRes.Kind == "PodSecurityPolicy" || iShieldRes.Name == "helmreleasemetadatas.apis.integrityshield.io" {
					continue
				}
				err := CheckIShieldResources(framework, iShieldRes.Kind, iShieldRes.Namespace, iShieldRes.Name)
				Expect(err).To(BeNil())
			}
		})
		It("Deleting ishield resources should be blocked", func() {
			if skip_default_user_test {
				Skip("This test should be executed by default user")
			}
			time.Sleep(time.Second * 15)
			framework := initFrameWork()
			// change kube context
			err := ChangeKubeContextToDefaultUser(framework, test_namespace, "default-token-")
			Expect(err).To(BeNil())
			// load ishield resource lists
			isc_name := "ishield-config"
			isc, err := framework.ShieldConfigClient.ShieldConfigs(ishield_namespace).Get(goctx.Background(), isc_name, metav1.GetOptions{})
			Expect(err).To(BeNil())
			ishield_resource_list := []*common.ResourceRef{}
			ishield_resource_list = append(ishield_resource_list, isc.Spec.ShieldConfig.IShieldResourceCondition.OperatorResources...)
			ishield_resource_list = append(ishield_resource_list, isc.Spec.ShieldConfig.IShieldResourceCondition.ServerResources...)
			By("Try to Delete ishield resources...")
			for _, iShieldRes := range ishield_resource_list {
				fmt.Print(iShieldRes.Kind, " : ", iShieldRes.Name, "\n")
				if iShieldRes.Name == "" || iShieldRes.Kind == "SecurityContextConstraints" || iShieldRes.Kind == "PodSecurityPolicy" || iShieldRes.Name == "helmreleasemetadatas.apis.integrityshield.io" {
					continue
				}
				if iShieldRes.Namespace != "" {
					cmd_err := Kubectl("delete", iShieldRes.Kind, iShieldRes.Name, "-n", iShieldRes.Namespace)
					Expect(cmd_err).NotTo(BeNil())
				} else {
					cmd_err := Kubectl("delete", iShieldRes.Kind, iShieldRes.Name)
					Expect(cmd_err).NotTo(BeNil())
				}
			}
			// change kube context
			err = ChangeKubeContextToKubeAdmin()
			Expect(err).To(BeNil())
		})
		It("Updating CR by iShieldAdmin should be allowed and iShield Resources should be changed", func() {
			if !local_test {
				Skip("This test is executed only in the local env.")
			}
			framework := initFrameWork()
			var timeout int = 120
			// shield config
			shc, err := framework.ShieldConfigClient.ShieldConfigs(ishield_namespace).Get(goctx.Background(), DefaultShieldConfigName, metav1.GetOptions{})
			Expect(err).To(BeNil())
			generation_shieldconfig := shc.Generation
			// update cr
			cmd_err := Kubectl("apply", "-f", integrityShieldOperatorCR_updated, "-n", ishield_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				shc, err := framework.ShieldConfigClient.ShieldConfigs(ishield_namespace).Get(goctx.Background(), DefaultShieldConfigName, metav1.GetOptions{})
				if err != nil {
					return err
				}
				if shc.Generation == generation_shieldconfig {
					return fmt.Errorf("ShieldConfig is not changed: %v", DefaultShieldConfigName)
				}
				return nil
			}, timeout, 1).Should(BeNil())
		})
		It("Updating ShieldConfig should be blocked", func() {
			framework := initFrameWork()
			var timeout int = 120
			expected := "ishield-config"
			cmd_err := Kubectl("apply", "-f", iShield_config_updated, "-n", ishield_namespace)
			Expect(cmd_err).NotTo(BeNil())
			Eventually(func() error {
				return CheckBlockEvent(framework, "direct-access-prohibited", ishield_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
	})

	Describe("Test integrity shield server", func() {
		It("Invalid format rsp can not be created", func() {
			framework := initFrameWork()
			var timeout int = 120
			expected := "test-rsp-invalid-format"
			cmd_err := Kubectl("apply", "-f", test_rsp_invalid, "-n", test_namespace)
			Expect(cmd_err).NotTo(BeNil())
			Eventually(func() error {
				return CheckBlockEvent(framework, "validation-fail", test_namespace, expected)
			}, timeout, 1).Should(BeNil())
		})
		Context("RSP in test ns is effective", func() {
			It("Resources should be unmonitored if rsp does not exist.", func() {
				framework := initFrameWork()
				var timeout int = 120
				expected := "test-configmap-unmonitored"
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
					_, err := framework.RSPClient.ResourceSigningProfiles().Get(goctx.Background(), expected, metav1.GetOptions{})
					if err != nil {
						return err
					}
					return nil
				}, timeout, 1).Should(BeNil())
			})
			It("Request is allowed if filtered by IgnoredKind", func() {
				framework := initFrameWork()
				var timeout int = 120
				cm_name := "test-configmap-deny-event"
				expected := "ishield-deny-create-configmap-test-configmap-deny-event"
				server_name := "integrity-shield-server"
				cmd_err := Kubectl("create", "cm", cm_name, "-n", test_namespace)
				Expect(cmd_err).NotTo(BeNil())
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
					return GetEvent(framework, test_namespace, expected)
				}, timeout, 1).Should(BeNil())
			})
			It("Unsigned resouce should be blocked", func() {
				framework := initFrameWork()
				var timeout int = 120
				expected := "test-configmap"
				cmd_err := Kubectl("apply", "-f", test_configmap, "-n", test_namespace)
				Expect(cmd_err).NotTo(BeNil())
				Eventually(func() error {
					return CheckBlockEvent(framework, "no-signature", test_namespace, expected)
				}, timeout, 1).Should(BeNil())
			})
			It("Signed resource which do not match SignerConfig should be blocked", func() {
				framework := initFrameWork()
				var timeout int = 120
				expected := "test-configmap-signer2"
				cmd_err := Kubectl("apply", "-f", test_configmap_signer2, "-n", test_namespace)
				Expect(cmd_err).NotTo(BeNil())
				Eventually(func() error {
					return CheckBlockEvent(framework, "no-match-signer-config", test_namespace, expected)
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
				expected := "test-configmap-annotation"
				cmd_err := Kubectl("apply", "-f", test_configmap_annotation, "-n", test_namespace)
				Expect(cmd_err).To(BeNil())
				Eventually(func() error {
					return CheckConfigMap(framework, test_namespace, expected)
				}, timeout, 1).Should(BeNil())
			})
			It("Changing protected rerouce should be blocked", func() {
				framework := initFrameWork()
				var timeout int = 120
				expected := "test-configmap"
				cmd_err := Kubectl("apply", "-f", test_configmap_updated, "-n", test_namespace)
				Expect(cmd_err).NotTo(BeNil())
				Eventually(func() error {
					return CheckBlockEvent(framework, "no-signature", test_namespace, expected)
				}, timeout, 1).Should(BeNil())
			})
			It("Changing whitelisted part should be allowed", func() {
				framework := initFrameWork()
				var timeout int = 120
				expected := "test-configmap"
				server_name := "integrity-shield-server"
				server := GetPodName(framework, ishield_namespace, server_name)
				// apply cm
				cmd_err := Kubectl("apply", "-f", test_configmap_ignoreAtters, "-n", test_namespace)
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
			It("Deleting a resource should be allowed even if protected", func() {
				var timeout int = 120
				expected := "test-configmap-annotation"
				cmd_err := Kubectl("delete", "-f", test_configmap_annotation, "-n", test_namespace)
				Expect(cmd_err).To(BeNil())
				Eventually(func() error {
					cmd_err = Kubectl("get", "cm", expected, "-n", test_namespace)
					return cmd_err
				}, timeout, 1).ShouldNot(BeNil())
			})
			It("Unsigned resource can be created if filtered by exclude rule", func() {
				framework := initFrameWork()
				var timeout int = 120
				expected := "test-configmap-excluded"
				cmd_err := Kubectl("create", "cm", expected, "-n", test_namespace)
				Expect(cmd_err).To(BeNil())
				Eventually(func() error {
					return CheckConfigMap(framework, test_namespace, expected)
				}, timeout, 1).Should(BeNil())
			})
			It("Prepare for deployment update test.", func() {
				framework := initFrameWork()
				var timeout int = 120
				expected := "test-deployment"
				cmd_err := Kubectl("apply", "-f", test_deployment, "-n", test_namespace)
				if cmd_err != nil {
					if cmd_exec_err, ok := cmd_err.(*exec.ExitError); ok {
						fmt.Printf("stderr:\n %s", string(cmd_exec_err.Stderr))
					}
				}
				Expect(cmd_err).To(BeNil())
				Eventually(func() error {
					return CheckDeployment(framework, test_namespace, expected)
				}, timeout, 1).Should(BeNil())
			})
			It("Newly added rule in RSP is effective", func() {
				framework := initFrameWork()
				var timeout int = 120
				cmd_err := Kubectl("apply", "-f", test_rsp_update, "-n", test_namespace)
				Expect(cmd_err).To(BeNil())
				expected := "test-configmap-unprotected"
				cmd_err = Kubectl("create", "cm", expected, "-n", test_namespace)
				Expect(cmd_err).To(BeNil())
				Eventually(func() error {
					return CheckConfigMap(framework, test_namespace, expected)
				}, timeout, 1).Should(BeNil())
			})
			It("Updating a signed deployment with kubectl apply should be allowed.", func() {
				framework := initFrameWork()
				var timeout int = 120
				expected := "test-deployment"
				cmd_err := Kubectl("apply", "-f", test_deployment_updated, "-n", test_namespace)
				Expect(cmd_err).To(BeNil())
				if cmd_err != nil {
					if cmd_exec_err, ok := cmd_err.(*exec.ExitError); ok {
						fmt.Printf("stderr:\n %s", string(cmd_exec_err.Stderr))
					}
				}
				server_name := "integrity-shield-server"
				server := GetPodName(framework, ishield_namespace, server_name)
				Eventually(func() error {
					// check forwarder log
					cmdstr := "kubectl logs " + server + " -c forwarder -n " + ishield_namespace + " | grep " + expected + " | grep valid-sig | grep UPDATE"
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
					_, err := framework.RSPClient.ResourceSigningProfiles().Get(goctx.Background(), expected, metav1.GetOptions{})
					return err
				}, timeout, 1).ShouldNot(BeNil())
			})
			It("Unsigned resouce should not be blocked after rsp is removed", func() {
				if !local_test {
					Skip("This test is executed only in the local env.")
				}
				framework := initFrameWork()
				var timeout int = 120
				expected := "test-configmap-unmonitored2"
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
				// time.Sleep(time.Second * 30)
				framework := initFrameWork()
				var timeout int = 120
				expected := "test-rsp"
				By("Creating test rsp: " + test_rsp_ishield + " ns: " + ishield_namespace)
				cmd_err := Kubectl("apply", "-f", test_rsp_ishield, "-n", ishield_namespace)
				Expect(cmd_err).To(BeNil())
				By("Checking rsp is created properly: " + test_rsp_ishield + " ns: " + ishield_namespace)
				Eventually(func() error {
					_, err := framework.RSPClient.ResourceSigningProfiles().Get(goctx.Background(), expected, metav1.GetOptions{})
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
				By("Creating new namespace: " + test_namespace_new)
				cmd_err := Kubectl("create", "ns", test_namespace_new)
				Expect(cmd_err).To(BeNil())
				By("Creating test configmap in ns: " + test_namespace_new)
				cmd_err = Kubectl("apply", "-f", test_configmap, "-n", test_namespace_new)
				Expect(cmd_err).NotTo(BeNil())
				Eventually(func() error {
					return CheckBlockEvent(framework, "no-signature", test_namespace_new, expected)
				}, timeout, 1).Should(BeNil())
			})
			It("Signed resource should be allowed in new namespace", func() {
				framework := initFrameWork()
				var timeout int = 120
				expected := "test-configmap-annotation"
				By("Creating test configmap in ns: " + test_namespace_new)
				cmd_err := Kubectl("apply", "-f", test_configmap_annotation, "-n", test_namespace_new)
				Expect(cmd_err).To(BeNil())
				Eventually(func() error {
					return CheckConfigMap(framework, test_namespace_new, expected)
				}, timeout, 1).Should(BeNil())
			})
			It("Resources in unmonitored ns can be created without signature", func() {
				framework := initFrameWork()
				var timeout int = 120
				expected := "test-configmap"
				By("Creating test configmap in ns: " + test_unprotected_namespace)
				cmd_err := Kubectl("apply", "-f", test_configmap, "-n", test_unprotected_namespace)
				Expect(cmd_err).To(BeNil())
				Eventually(func() error {
					return CheckConfigMap(framework, test_unprotected_namespace, expected)
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
			server_name := "integrity-shield-server"
			server := GetPodName(framework, ishield_namespace, server_name)
			err, serverLog := KubectlOut("logs", "-n", ishield_namespace, server, "-c", "server")
			Expect(err).To(BeNil())
			_ = ioutil.WriteFile("./e2etest-server.log", []byte(serverLog), 0640) // NO SONAR

			err, forwarderLog := KubectlOut("logs", "-n", ishield_namespace, server, "-c", "forwarder")
			Expect(err).To(BeNil())
			_ = ioutil.WriteFile("./e2etest-forwarder.log", []byte(forwarderLog), 0640) // NO SONAR

			isc_name := "ishield-config"
			By("Load ishield resource list")
			isc, err := framework.ShieldConfigClient.ShieldConfigs(ishield_namespace).Get(goctx.Background(), isc_name, metav1.GetOptions{})
			Expect(err).To(BeNil())
			ishield_resource_list := []*common.ResourceRef{}
			ishield_resource_list = append(ishield_resource_list, isc.Spec.ShieldConfig.IShieldResourceCondition.OperatorResources...)
			ishield_resource_list = append(ishield_resource_list, isc.Spec.ShieldConfig.IShieldResourceCondition.ServerResources...)
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
			for _, iShieldRes := range ishield_resource_list {
				fmt.Print(iShieldRes.Kind, " : ", iShieldRes.Name, "\n")
				if iShieldRes.Name == "" || iShieldRes.Kind == "IntegrityShield" || iShieldRes.Kind == "SecurityContextConstraints" || iShieldRes.Kind == "PodSecurityPolicy" || iShieldRes.Name == "integrity-shield-operator-controller-manager" || iShieldRes.Name == "helmreleasemetadatas.apis.integrityshield.io" || iShieldRes.Name == "integrityshields.apis.integrityshield.io" {
					continue
				}
				err := CheckIShieldResources(framework, iShieldRes.Kind, iShieldRes.Namespace, iShieldRes.Name)
				if err == nil {
					fmt.Println("[DEBUG1] ", iShieldRes.Kind, " : ", iShieldRes.Name)
				} else {
					fmt.Println("[DEBUG2] ", iShieldRes.Kind, " : ", iShieldRes.Name, ", err: ", err.Error())
				}
				// Expect(err).NotTo(BeNil())
			}
		})
	})
})
