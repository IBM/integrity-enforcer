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
	"context"

	rsigclient "github.com/IBM/integrity-enforcer/shield/pkg/client/resourcesignature/clientset/versioned/typed/resourcesignature/v1alpha1"
	rspclient "github.com/IBM/integrity-enforcer/shield/pkg/client/resourcesigningprofile/clientset/versioned/typed/resourcesigningprofile/v1alpha1"
	sconfclient "github.com/IBM/integrity-enforcer/shield/pkg/client/shieldconfig/clientset/versioned/typed/shieldconfig/v1alpha1"
	sigconfclient "github.com/IBM/integrity-enforcer/shield/pkg/client/signerconfig/clientset/versioned/typed/signerconfig/v1alpha1"

	rsigapi "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesignature/v1alpha1"
	rspapi "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesigningprofile/v1alpha1"
	sconfapi "github.com/IBM/integrity-enforcer/shield/pkg/apis/shieldconfig/v1alpha1"
	sigconfapi "github.com/IBM/integrity-enforcer/shield/pkg/apis/signerconfig/v1alpha1"
	kubeutil "github.com/IBM/integrity-enforcer/shield/pkg/util/kubeutil"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type Loader struct {
	IShiledNamespace string
	ShieldConfigName string
}

type RuntimeData struct {
	ShieldConfig *sconfapi.ShieldConfig
	SigConfList  *sigconfapi.SignerConfigList
	RSPList      *rspapi.ResourceSigningProfileList
	NSList       *v1.NamespaceList
	ResSigList   *rsigapi.ResourceSignatureList
	PodList      *v1.PodList
}

func NewLoader(iShieldNS, shieldConfigName string) *Loader {
	return &Loader{
		IShiledNamespace: iShieldNS,
		ShieldConfigName: shieldConfigName,
	}
}

func (self *Loader) Load() (*RuntimeData, error) {
	var data *RuntimeData
	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		return nil, err
	}

	data = &RuntimeData{}

	sConfClient, err := sconfclient.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	sConf, err := sConfClient.ShieldConfigs(self.IShiledNamespace).Get(context.Background(), self.ShieldConfigName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	data.ShieldConfig = sConf

	sigConfClient, err := sigconfclient.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	sigConfList, err := sigConfClient.SignerConfigs(self.IShiledNamespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	data.SigConfList = sigConfList

	rspClient, err := rspclient.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	rspList, err := rspClient.ResourceSigningProfiles("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	data.RSPList = rspList

	rsigClient, err := rsigclient.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	rsigList, err := rsigClient.ResourceSignatures("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	data.ResSigList = rsigList

	k8sClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	nsList, err := k8sClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	data.NSList = nsList

	podList, err := k8sClient.CoreV1().Pods(self.IShiledNamespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	data.PodList = podList

	return data, nil
}
