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

package config

import (
	"log"

	ecfgclient "github.com/IBM/integrity-enforcer/enforcer/pkg/client/enforcerconfig/clientset/versioned/typed/enforcerconfig/v1alpha1"
	cfg "github.com/IBM/integrity-enforcer/enforcer/pkg/config"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/rest"
)

func LoadEnforceConfig(namespace, cmname string) *cfg.EnforcerConfig {

	config, err := rest.InClusterConfig()
	if err != nil {
		return nil
	}
	clientset, err := ecfgclient.NewForConfig(config)
	if err != nil {
		log.Fatal(err)
		return nil
	}
	ecres, err := clientset.EnforcerConfigs(namespace).Get(cmname, metav1.GetOptions{})
	if err != nil {
		log.Fatalln("failed to get EnforcerConfig:", err)
		return nil
	}

	ec := ecres.Spec.EnforcerConfig
	return ec
}
