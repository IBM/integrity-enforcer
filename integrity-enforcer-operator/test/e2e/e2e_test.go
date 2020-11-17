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
	"strings"
	"time"

	// "testing"

	. "github.com/onsi/ginkgo" //nolint:golint
	. "github.com/onsi/gomega" //nolint:golint

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Test integrity enforcer handling", func() {
	Describe("Check operator status in ns:"+ie_namespace, func() {
		It("should be Running Status", func() {
			var timeout int = 120
			var wantFound bool = false
			expected := "integrity-enforcer-operator-controller-manager"
			framework := initFrameWork()
			Eventually(func() error {
				var err error
				pods, err := framework.KubeClientSet.CoreV1().Pods(framework.Namespace.Name).List(goctx.TODO(), metav1.ListOptions{})
				if err != nil {
					return err
				}
				pod_exist := false
				for _, pod := range pods.Items {
					if strings.HasPrefix(pod.Name, expected) {
						pod_exist = true
						all_container_running := true
						for _, c := range pod.Status.ContainerStatuses {
							if !c.Ready {
								all_container_running = false
							}
						}
						if all_container_running {
							wantFound = true
						}
					}
				}
				if !pod_exist && err == nil {
					return fmt.Errorf("expected to return IsNotFound error")
				}
				if !wantFound && err == nil {
					return fmt.Errorf("expected to return IsNotRunning error")
				}
				if !wantFound && err != nil && !errors.IsNotFound(err) {
					return err
				}
				return nil
			}, timeout, 1).Should(BeNil())
		})
	})
	Describe("Install ie server in ns:"+ie_namespace, func() {
		It("should be created properly", func() {
			By("Creating cr: " + integrityEnforcerOperatorCR)
			var timeout int = 300
			var wantFound bool = false
			expected := "integrity-enforcer-server"
			framework := initFrameWork()
			cmd_err := Kubectl("apply", "-f", integrityEnforcerOperatorCR, "-n", ie_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				var err error
				pods, err := framework.KubeClientSet.CoreV1().Pods(ie_namespace).List(goctx.TODO(), metav1.ListOptions{})
				if err != nil {
					return err
				}
				pod_exist := false
				for _, pod := range pods.Items {
					if strings.HasPrefix(pod.Name, expected) {
						pod_exist = true
						for _, pod := range pods.Items {
							if strings.HasPrefix(pod.Name, expected) {
								pod_exist = true
								// all_container_running := true
								// for _, c := range pod.Status.ContainerStatuses {
								// 	if !c.Ready {
								// 		all_container_running = false
								// 	}
								// }
								// if all_container_running {
								// 	wantFound = true
								// }
								if pod.Status.Phase == "Running" {
									wantFound = true
								}
							}
						}
						// if pod.Status.Phase == "Running" {
						// 	wantFound = true
						// }
					}
				}
				if !pod_exist && err == nil {
					return fmt.Errorf("expected to return IsNotFound error")
				}
				if !wantFound && err == nil {
					return fmt.Errorf("expected to return IsNotRunning error")
				}
				if !wantFound && err != nil && !errors.IsNotFound(err) {
					return err
				}
				return nil
			}, timeout, 1).Should(BeNil())
		})
	})
	Describe("Check integrity enforcer resource CRDs", func() {
		framework := initFrameWork()
		It("EnforcerConfig should be created properly", func() {
			expected := "enforcerconfigs.apis.integrityenforcer.io"
			ec, err := framework.APIExtensionsClientSet.ApiextensionsV1().CustomResourceDefinitions().Get(goctx.Background(), expected, metav1.GetOptions{})
			if err != nil {
				fmt.Errorf("CRD is not created: %v", expected)
			}
			if ec.Name != expected {
				fmt.Errorf("CRD is not created: %v", expected)
			}
		})
		It("ResourceSignature should be created properly", func() {
			expected := "resourcesignatures.apis.integrityenforcer.io"
			rs, err := framework.APIExtensionsClientSet.ApiextensionsV1().CustomResourceDefinitions().Get(goctx.Background(), expected, metav1.GetOptions{})
			if err != nil {
				fmt.Errorf("CRD is not created: %v", expected)
			}
			if rs.Name != expected {
				fmt.Errorf("CRD is not created: %v", expected)
			}
		})
		It("ResourceSigningProfile should be created properly", func() {
			expected := "resourcesigningprofiles.apis.integrityenforcer.io"
			rsp, err := framework.APIExtensionsClientSet.ApiextensionsV1().CustomResourceDefinitions().Get(goctx.Background(), expected, metav1.GetOptions{})
			if err != nil {
				fmt.Errorf("CRD is not created: %v", expected)
			}
			if rsp.Name != expected {
				fmt.Errorf("CRD is not created: %v", expected)
			}
		})
		It("SignPolicy should be created properly", func() {
			expected := "signpolicies.apis.integrityenforcer.io"
			sp, err := framework.APIExtensionsClientSet.ApiextensionsV1().CustomResourceDefinitions().Get(goctx.Background(), expected, metav1.GetOptions{})
			if err != nil {
				fmt.Errorf("CRD is not created: %v", expected)
			}
			if sp.Name != expected {
				fmt.Errorf("CRD is not created: %v", expected)
			}
		})
	})

	var _ = Describe("Test integrity enforcer function", func() {
		framework := initFrameWork()
		It("Test rsp should be created properly", func() {
			time.Sleep(time.Second * 30)
			var timeout int = 120
			expected := "test-rsp"
			By("Creating test rsp: " + test_rsp + " ns: " + test_namespace)
			cmd_err := Kubectl("apply", "-f", test_rsp, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				var err error
				rsp, err := framework.RSPClient.ResourceSigningProfiles(test_namespace).Get(goctx.Background(), expected, metav1.GetOptions{})
				if err != nil {
					return err
				}
				if len(rsp.Spec.ProtectRules) == 0 {
					fmt.Errorf("ProtectRules is nil: %v", expected)
				}
				return nil
			}, timeout, 1).Should(BeNil())
		})
		It("Test unsigned resouce should be blocked", func() {
			time.Sleep(time.Second * 15)
			var timeout int = 60
			expected := "test-configmap"
			By("Creating test configmap in ns: " + test_namespace + " : " + test_configmap)
			cmd_err := Kubectl("apply", "-f", test_configmap, "-n", test_namespace)
			Expect(cmd_err).NotTo(BeNil())
			Eventually(func() error {
				events, err := framework.KubeClientSet.CoreV1().Events(test_namespace).List(goctx.TODO(), metav1.ListOptions{})
				// _, err := framework.KubeClientSet.CoreV1().ConfigMaps(test_namespace).Get(goctx.TODO(), expected, metav1.GetOptions{})
				if err != nil {
					return err
				}
				blocked := false
				for _, event := range events.Items {
					if event.Reason == "no-signature" && strings.HasSuffix(event.Name, expected) {
						blocked = true
					}
				}
				if !blocked {
					fmt.Errorf("Fail to block: %v", expected)
				}
				return nil
			}, timeout, 1).Should(BeNil())
		})
		It("Test signed resouce should be allowed", func() {
			time.Sleep(time.Second * 15)
			var timeout int = 60
			expected := "test-configmap-signed"
			By("Creating resource signature in ns: " + test_namespace)
			cmd_err := Kubectl("apply", "-f", test_configmap2_rs, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			By("Creating test configmap in ns: " + test_namespace)
			cmd_err = Kubectl("apply", "-f", test_configmap2, "-n", test_namespace)
			Expect(cmd_err).To(BeNil())
			Eventually(func() error {
				_, err := framework.KubeClientSet.CoreV1().ConfigMaps(test_namespace).Get(goctx.TODO(), expected, metav1.GetOptions{})
				if err != nil {
					return err
				}
				return nil
			}, timeout, 1).Should(BeNil())
		})
	})
})
