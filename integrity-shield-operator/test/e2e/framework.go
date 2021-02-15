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

package e2e

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	. "github.com/onsi/ginkgo" //nolint:golint

	rspclient "github.com/IBM/integrity-enforcer/shield/pkg/client/resourcesigningprofile/clientset/versioned/typed/resourcesigningprofile/v1alpha1"
	vcclient "github.com/IBM/integrity-enforcer/shield/pkg/client/shieldconfig/clientset/versioned/typed/shieldconfig/v1alpha1"
	sigconfclient "github.com/IBM/integrity-enforcer/shield/pkg/client/signerconfig/clientset/versioned/typed/signerconfig/v1alpha1"
	v1 "k8s.io/api/core/v1"
	apiextcs "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	clientcmdlatest "k8s.io/client-go/tools/clientcmd/api/latest"

	// "k8s.io/client-go/tools/events"
	"k8s.io/klog"
)

var (
	// kubeconfigPath    = os.Getenv("KUBECONFIG")
	local_test, _                     = strconv.ParseBool(os.Getenv("TEST_LOCAL"))
	skip_default_user_test            = true
	kubeconfig_user                   = os.Getenv("KUBE_CONTEXT_USERNAME")
	ishield_namespace                 = os.Getenv("ISHIELD_OP_NS")
	test_namespace                    = os.Getenv("TEST_NS")
	test_namespace_new                = os.Getenv("TEST_NS_NEW")
	test_unprotected_namespace        = os.Getenv("TEST_UNPROTECTED_NS")
	shield_dir                        = os.Getenv("SHIELD_OP_DIR")
	deploy_dir                        = shield_dir + "test/deploy/"
	kubeconfigManaged                 = os.Getenv("KUBECONFIG")
	tmpDir                            = os.Getenv("TMP_DIR")
	integrityShieldOperatorCR         = tmpDir + "apis_v1alpha1_integrityshield.yaml"
	integrityShieldOperatorCR_updated = tmpDir + "apis_v1alpha1_integrityshield_update.yaml"
	iShield_config_updated            = deploy_dir + "ishield-config-update.yaml"
	test_rsp                          = deploy_dir + "test-rsp.yaml"
	test_rsp_update                   = deploy_dir + "test-rsp-update.yaml"
	test_rsp_ishield                  = deploy_dir + "test-rsp-ishield-ns.yaml"
	test_rsp_invalid                  = deploy_dir + "test-rsp-invalid-format.yaml"
	test_configmap                    = deploy_dir + "test-configmap.yaml"
	test_configmap_signer2            = deploy_dir + "test-configmap-signer2.yaml"
	test_configmap_updated            = deploy_dir + "test-configmap-update.yaml"
	test_configmap_ignoreAtters       = deploy_dir + "test-configmap-update-ignoreAtters.yaml"
	test_configmap_annotation         = deploy_dir + "test-configmap-annotation.yaml"
	test_configmap_rs                 = deploy_dir + "test-configmap-rs.yaml"
	DefaultSignerConfigName           = "signer-config"
	DefaultShieldConfigName           = "ishield-config"
)

type Framework struct {
	BaseName string

	KubeConfig  string
	KubeContext string
	Kubectl     string

	// KubeClientConfig which was used to create the connection.
	KubeClientConfig *rest.Config

	// Kubernetes API clientsets
	KubeClientSet          kubernetes.Interface
	APIExtensionsClientSet apiextcs.Interface
	RSPClient              rspclient.ApisV1alpha1Interface
	SignerConfigClient     sigconfclient.ApisV1alpha1Interface
	ShieldConfigClient     vcclient.ApisV1alpha1Interface

	// Namespace in which all test resources should reside
	Namespace *v1.Namespace
}

func initFrameWork() *Framework {
	framework := &Framework{
		KubeConfig: kubeconfigManaged,
	}
	kubeConfig, err := LoadConfig(framework.KubeConfig, framework.KubeContext)
	if err != nil {
		Fail(fmt.Sprintf("fail to set kubeconfig"))
	}
	framework.KubeClientSet, err = kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		Fail(fmt.Sprintf("fail to set KubeClientSet"))

	}
	framework.APIExtensionsClientSet, err = apiextcs.NewForConfig(kubeConfig)
	if err != nil {
		Fail(fmt.Sprintf("fail to set APIExtensionsClientSet"))
	}
	framework.RSPClient, err = rspclient.NewForConfig(kubeConfig)
	if err != nil {
		Fail(fmt.Sprintf("fail to set RSPClient"))
	}
	framework.SignerConfigClient, err = sigconfclient.NewForConfig(kubeConfig)
	if err != nil {
		Fail(fmt.Sprintf("fail to set SignerConfigClient"))
	}

	framework.ShieldConfigClient, err = vcclient.NewForConfig(kubeConfig)
	if err != nil {
		Fail(fmt.Sprintf("fail to set ShieldConfigClient"))
	}
	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: ishield_namespace,
		},
	}
	framework.Namespace = ns
	return framework
}

func LoadConfig(config, context string) (*rest.Config, error) {
	c, err := RestclientConfig(config, context)
	if err != nil {
		return nil, err
	}
	return clientcmd.NewDefaultClientConfig(*c, &clientcmd.ConfigOverrides{}).ClientConfig()
}

func RestclientConfig(config, context string) (*clientcmdapi.Config, error) {
	if config == "" {
		return nil, fmt.Errorf("Config file must be specified to load client config")
	}
	c, err := clientcmd.LoadFromFile(config)
	if err != nil {
		return nil, fmt.Errorf("error loading config: %v", err.Error())
	}
	if context != "" {
		c.CurrentContext = context
	}
	return c, nil
}
func Load(data []byte) (*clientcmdapi.Config, error) {
	config := clientcmdapi.NewConfig()
	// if there's no data in a file, return the default object instead of failing (DecodeInto reject empty input)
	if len(data) == 0 {
		return config, nil
	}
	decoded, _, err := clientcmdlatest.Codec.Decode(data, &schema.GroupVersionKind{Version: clientcmdlatest.Version, Kind: "Config"}, config)
	if err != nil {
		return nil, err
	}
	return decoded.(*clientcmdapi.Config), nil
}
func LoadFromFile(filename string) (*clientcmdapi.Config, error) {
	kubeconfigBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	config, err := Load(kubeconfigBytes)
	if err != nil {
		return nil, err
	}
	klog.V(6).Infoln("Config loaded from file: ", filename)

	// set LocationOfOrigin on every Cluster, User, and Context
	for key, obj := range config.AuthInfos {
		obj.LocationOfOrigin = filename
		config.AuthInfos[key] = obj
	}
	for key, obj := range config.Clusters {
		obj.LocationOfOrigin = filename
		config.Clusters[key] = obj
	}
	for key, obj := range config.Contexts {
		obj.LocationOfOrigin = filename
		config.Contexts[key] = obj
	}

	if config.AuthInfos == nil {
		config.AuthInfos = map[string]*clientcmdapi.AuthInfo{}
	}
	if config.Clusters == nil {
		config.Clusters = map[string]*clientcmdapi.Cluster{}
	}
	if config.Contexts == nil {
		config.Contexts = map[string]*clientcmdapi.Context{}
	}

	return config, nil
}
