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
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1beta1 "k8s.io/api/admission/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/envtest/printer"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	rs "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesignature/v1alpha1"
	rsp "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesigningprofile/v1alpha1"
	rspapi "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesigningprofile/v1alpha1"
	ec "github.com/IBM/integrity-enforcer/shield/pkg/apis/shieldconfig/v1alpha1"
	sigconf "github.com/IBM/integrity-enforcer/shield/pkg/apis/signerconfig/v1alpha1"
	common "github.com/IBM/integrity-enforcer/shield/pkg/common"
	config "github.com/IBM/integrity-enforcer/shield/pkg/shield/config"
	"github.com/IBM/integrity-enforcer/shield/pkg/util/kubeutil"
	"github.com/IBM/integrity-enforcer/shield/pkg/util/logger"
	scc "github.com/openshift/api/security/v1"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	// +kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var k8sClient client.Client
var testEnv *envtest.Environment
var schemes *runtime.Scheme

var req *v1beta1.AdmissionRequest
var testConfig *config.ShieldConfig

func getTestData(num int) (*common.ReqContext, *config.ShieldConfig, *RunData, *CheckContext, *DecisionResult, rspapi.ResourceSigningProfile, *DecisionResult) {

	var reqc *common.ReqContext

	var data *RunData
	var ctx *CheckContext
	var dr0 *DecisionResult
	var prof rspapi.ResourceSigningProfile
	var dr *DecisionResult

	reqcBytes, _ := ioutil.ReadFile(testFileName(testReqcFile, num))
	configBytes, _ := ioutil.ReadFile(testFileName(testConfigFile, num))
	dataBytes, _ := ioutil.ReadFile(testFileName(testDataFile, num))
	ctxBytes, _ := ioutil.ReadFile(testFileName(testCtxFile, num))
	//drBytes, _ := ioutil.ReadFile(testDrFile)
	profBytes, _ := ioutil.ReadFile(testFileName(testProfFile, num))
	drBytes, _ := ioutil.ReadFile(testFileName(testDrFile, num))
	_ = json.Unmarshal(reqcBytes, &reqc)
	_ = json.Unmarshal(configBytes, &testConfig)
	_ = json.Unmarshal(dataBytes, &data)
	_ = json.Unmarshal(ctxBytes, &ctx)
	//_ = json.Unmarshal(drBytes, &dr)
	_ = json.Unmarshal(profBytes, &prof)
	_ = json.Unmarshal(drBytes, &dr)
	dr0 = &DecisionResult{
		Type: common.DecisionUndetermined,
	}
	var req *v1beta1.AdmissionRequest
	_ = json.Unmarshal([]byte(reqc.RequestJsonStr), &req)
	if req != nil {
		reqc.RawObject = req.Object.Raw
		reqc.RawOldObject = req.OldObject.Raw
	}
	return reqc, testConfig, data, ctx, dr0, prof, dr
}

func getChangedRequest(req *v1beta1.AdmissionRequest) *v1beta1.AdmissionRequest {
	var newReq *v1beta1.AdmissionRequest
	reqBytes, _ := json.Marshal(req)
	_ = json.Unmarshal(reqBytes, &newReq)
	var cm *v1.ConfigMap
	_ = json.Unmarshal(newReq.Object.Raw, &cm)
	cm.Data["key3"] = "val3"
	newReq.Object.Raw, _ = json.Marshal(cm)
	return newReq
}

func TestHandler(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecsWithDefaultAndCustomReporters(t,
		"Controller Suite",
		[]Reporter{printer.NewlineReporter{}})
}

var _ = BeforeSuite(func(done Done) {
	logf.SetLogger(zap.LoggerTo(GinkgoWriter, true))

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{filepath.Join(".", "testdata", "crds")},
	}

	var err error
	cfg, err := testEnv.Start()
	Expect(err).ToNot(HaveOccurred())
	Expect(cfg).ToNot(BeNil())

	schemes = runtime.NewScheme()
	err = clientgoscheme.AddToScheme(schemes)
	err = apiextensionsv1.AddToScheme(schemes)
	err = apiextensionsv1beta1.AddToScheme(schemes)

	err = scc.AddToScheme(schemes)
	err = ec.AddToScheme(schemes)
	err = rsp.AddToScheme(schemes)
	err = rs.AddToScheme(schemes)
	err = sigconf.AddToScheme(schemes)

	Expect(err).NotTo(HaveOccurred())

	// +kubebuilder:scaffold:scheme

	kubeutil.SetKubeConfig(cfg)

	k8sClient, err = client.New(cfg, client.Options{Scheme: schemes})
	Expect(err).ToNot(HaveOccurred())
	Expect(k8sClient).ToNot(BeNil())

	reqc, testConfig, data, _, _, _, _ := getTestData(1)
	reqBytes := []byte(reqc.RequestJsonStr)
	err = json.Unmarshal(reqBytes, &req)
	Expect(err).Should(BeNil())
	Expect(req).ToNot(BeNil())

	logger.InitServerLogger(testConfig.LoggerConfig())
	logger.InitContextLogger(testConfig.ContextLoggerConfig())

	err = k8sClient.Create(context.Background(), &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testConfig.Namespace}})
	Expect(err).Should(BeNil())

	// create namespaces in test data
	for _, nsData := range data.NSList {
		ns := &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: nsData.Name},
		}
		_ = k8sClient.Create(context.Background(), ns)
	}

	// create ShieldConfig in test data
	sconf := &ec.ShieldConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "ishield-config", Namespace: testConfig.Namespace},
		Spec:       ec.ShieldConfigSpec{ShieldConfig: testConfig},
	}
	err = k8sClient.Create(context.Background(), sconf)
	Expect(err).Should(BeNil())

	// create SignerConfig in test data
	sigconfres := &sigconf.SignerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: data.SignerConfig.Name, Namespace: data.SignerConfig.Namespace},
		Spec:       sigconf.SignerConfigSpec{Config: data.SignerConfig.Spec.Config.DeepCopy()},
	}
	err = k8sClient.Create(context.Background(), sigconfres)
	Expect(err).Should(BeNil())

	// create rsps in test data
	for _, rsp := range data.RSPList {
		rsp.ObjectMeta = metav1.ObjectMeta{Name: rsp.Name, Namespace: rsp.Namespace}
		err = k8sClient.Create(context.Background(), &rsp)
		Expect(err).Should(BeNil())
	}

	// create ressigs in test data
	for _, rsig := range data.ResSigList.Items {
		rsig.ObjectMeta = metav1.ObjectMeta{Name: rsig.Name, Namespace: rsig.Namespace}
		err = k8sClient.Create(context.Background(), rsig)
		Expect(err).Should(BeNil())
	}

	close(done)
}, 60)

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).ToNot(HaveOccurred())
})

var _ = Describe("Test integrity shield", func() {
	It("Handler Run Test (allow, no-mutation)", func() {
		var timeout int = 10
		Eventually(func() error {
			testHandler := NewHandler(testConfig)
			resp := testHandler.Run(req)
			respBytes, _ := json.Marshal(resp)
			fmt.Printf("[TestInfo] respBytes: %s", string(respBytes))
			if resp == nil {
				return fmt.Errorf("Run() returns nil as AdmissionResponse")
			} else if !strings.Contains(resp.Result.Message, "no mutation") {
				return fmt.Errorf("Run() returns wrong AdmissionResponse")
			}
			return nil
		}, timeout, 1).Should(BeNil())
	})
	It("Handler Run Test (deny, signature-not-identical)", func() {
		var timeout int = 10
		Eventually(func() error {
			testHandler := NewHandler(testConfig)
			changedReq := getChangedRequest(req)
			resp := testHandler.Run(changedReq)
			respBytes, _ := json.Marshal(resp)
			fmt.Printf("[TestInfo] respBytes: %s", string(respBytes))
			if resp == nil {
				return fmt.Errorf("Run() returns nil as AdmissionResponse")
			} else if !strings.Contains(resp.Result.Message, "not identical") {
				return fmt.Errorf("Run() returns wrong AdmissionResponse")
			}
			return nil
		}, timeout, 1).Should(BeNil())
	})

})
