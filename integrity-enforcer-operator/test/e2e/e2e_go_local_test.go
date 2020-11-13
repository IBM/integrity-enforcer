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

	// "testing"

	. "github.com/onsi/ginkgo" //nolint:golint
	. "github.com/onsi/gomega" //nolint:golint

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const integrityEnforcerOperatorCR = "../../config/samples/apis_v1alpha1_integrityenforcer_local.yaml"

var _ = Describe("Test integrity enforcer server handling", func() {
	Describe("Check operator status in ns:"+namespace, func() {
		It("should be Running Status", func() {
			var timeout int = 60
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
						if pod.Status.Phase == "Running" {
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
			Kubectl("apply", "-f", integrityEnforcerOperatorCR, "-n", ie_namespace)
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
						if pod.Status.Phase == "Running" {
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
})

// func TestIntegrityEnforcer(t *testing.T) {
// 	flag.StringVar(&kubeconfigManaged, "kubeconfig_managed", "../../kubeconfig_managed", "Location of the kubeconfig to use; defaults to KUBECONFIG if not set")

// 	t.Run("OperatorRunningTest", OperatorRunningTest)
// 	t.Run("InstallServerTest", InstallServerTest)
// 	t.Run("IntegrityEnforcerTestBasic", IntegrityEnforcerTestBasic)
// 	t.Run("IntegrityEnforcerServerRunningTest", IntegrityEnforcerServerRunningTest)
// 	t.Run("RSPTest", RSPTest)
// }

// func OperatorRunningTest(t *testing.T) {
// 	expected := "integrity-enforcer-operator-controller-manager"
// 	framework := initFrameWork()
// 	pods, err := framework.KubeClientSet.CoreV1().Pods(framework.Namespace.Name).List(goctx.TODO(), metav1.ListOptions{})
// 	if err != nil {
// 		t.Errorf("fail to get pods")
// 	} else {
// 		pod_exist := false
// 		for _, pod := range pods.Items {
// 			if strings.HasPrefix(pod.Name, expected) {
// 				pod_exist = true
// 				if pod.Status.Phase != "Running" {
// 					t.Errorf("pods status: %v", pod.Status.Phase)
// 				}
// 			}
// 		}
// 		if !pod_exist {
// 			t.Errorf("ie server is not exist")
// 		}
// 	}
// }

// func InstallServerTest(t *testing.T) {
// 	var timeout int = 120
// 	var wantFound bool = false
// 	expected := "integrity-enforcer-server"
// 	framework := initFrameWork()
// 	Kubectl("apply", "-f", integrityEnforcerOperatorCR, "-n", framework.Namespace.Name)
// 	Eventually(func() error {
// 		var err error
// 		pods, err := framework.KubeClientSet.CoreV1().Pods(framework.Namespace.Name).List(goctx.TODO(), metav1.ListOptions{})
// 		if err != nil {
// 			return err
// 		}
// 		pod_exist := false
// 		for _, pod := range pods.Items {
// 			if strings.HasPrefix(pod.Name, expected) {
// 				pod_exist = true
// 				if pod.Status.Phase == "Running" {
// 					wantFound = true
// 				}
// 			}
// 		}
// 		if !pod_exist && err == nil {
// 			return fmt.Errorf("expected to return IsNotFound error")
// 		}
// 		if !wantFound && err == nil {
// 			return fmt.Errorf("expected to return IsNotRunning error")
// 		}
// 		if !wantFound && err != nil && !errors.IsNotFound(err) {
// 			return err
// 		}
// 		return nil
// 	}, timeout, 1).Should(BeNil())
// }

// func RSPTest(t *testing.T) {
// 	expected := "sample-rsp"
// 	framework := initFrameWork()
// 	rsp, err := framework.RSPClient.ResourceSigningProfiles(framework.Namespace.Name).Get(goctx.Background(), expected, metav1.GetOptions{})
// 	if err != nil {
// 		t.Errorf("fail to get rsp: %v", expected)
// 	} else {
// 		if len(rsp.Spec.ProtectRules) == 0 {
// 			t.Errorf("ProtectRules is nil: %v", expected)
// 		}
// 	}
// }

// func IntegrityEnforcerServerRunningTest(t *testing.T) {
// 	expected := "integrity-enforcer-server"
// 	framework := initFrameWork()
// 	pods, err := framework.KubeClientSet.CoreV1().Pods(framework.Namespace.Name).List(goctx.TODO(), metav1.ListOptions{})
// 	if err != nil {
// 		t.Errorf("fail to get pods")
// 	} else {
// 		pod_exist := false
// 		for _, pod := range pods.Items {
// 			if strings.HasPrefix(pod.Name, expected) {
// 				pod_exist = true
// 				if pod.Status.Phase != "Running" {
// 					t.Errorf("pods status: %v", pod.Status.Phase)
// 				}
// 			}
// 		}
// 		if !pod_exist {
// 			t.Errorf("ie server is not exist")
// 		}
// 	}
// }

// func IntegrityEnforcerTestBasic(t *testing.T) {
// 	expected := "keyring-secret"
// 	framework := initFrameWork()
// 	secret, err := framework.KubeClientSet.CoreV1().Secrets(framework.Namespace.Name).Get(goctx.TODO(), expected, metav1.GetOptions{})
// 	if err != nil {
// 		t.Errorf("fail to get secret: %v", expected)
// 	} else {
// 		if secret.Name != expected {
// 			t.Errorf("got: %v\nwant: %v", secret.Name, expected)
// 		}
// 	}
// }

// var _ = Describe("Running Go projects", func() {
// 	Context("built with operator-sdk", func() {

// 		BeforeEach(func() {
// 			By("installing CRD's")
// 		})

// 		AfterEach(func() {
// 			By("uninstalling CRD's")
// 		})

// 		It("should run correctly locally", func() {
// 			By("running the project")
// 			cmd := exec.Command("make", "run")
// 			err := cmd.Start()
// 			Expect(err).NotTo(HaveOccurred())

// 			By("killing the project")
// 			err = cmd.Process.Kill()
// 			Expect(err).NotTo(HaveOccurred())
// 		})
// 	})
// })
