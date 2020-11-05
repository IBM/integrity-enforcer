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

package loader

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

const DefaultResourceLockCMName = "ie-resource-lock"

// LockConfigLoader
type LockConfigLoader struct {
	coreV1Client      *v1client.CoreV1Client
	data              map[string]string
	enforcerNamespace string
}

func NewLockConfigLoader(enforcerNamespace string) *LockConfigLoader {
	config, _ := rest.InClusterConfig()
	coreV1Client, err := v1client.NewForConfig(config)
	if err != nil {
		return nil
	}

	cm, err := coreV1Client.ConfigMaps(enforcerNamespace).Get(context.Background(), DefaultResourceLockCMName, metav1.GetOptions{})
	if err != nil {
		return nil
	}

	return &LockConfigLoader{
		coreV1Client:      coreV1Client,
		data:              cm.Data,
		enforcerNamespace: enforcerNamespace,
	}
}

func (self *LockConfigLoader) GetData() map[string]string {
	self.Load()
	return self.data
}

func (self *LockConfigLoader) Load() {
	cm, err := self.coreV1Client.ConfigMaps(self.enforcerNamespace).Get(context.Background(), DefaultResourceLockCMName, metav1.GetOptions{})
	if err != nil {
		return
	}
	self.data = cm.Data
	return
}
