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

package main

import (
	"context"
	"encoding/json"
	"time"

	rspapi "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesigningprofile/v1alpha1"
	rspclient "github.com/IBM/integrity-enforcer/shield/pkg/client/resourcesigningprofile/clientset/versioned/typed/resourcesigningprofile/v1alpha1"
	common "github.com/IBM/integrity-enforcer/shield/pkg/common"
	cache "github.com/IBM/integrity-enforcer/shield/pkg/util/cache"
	"github.com/IBM/integrity-enforcer/shield/pkg/util/kubeutil"

	logger "github.com/IBM/integrity-enforcer/shield/pkg/util/logger"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ResourceSigningProfile

type RSPLoader struct {
	defaultProfileInterval time.Duration

	Client *rspclient.ApisV1alpha1Client
	Data   []rspapi.ResourceSigningProfile
}

func NewRSPLoader() *RSPLoader {
	defaultProfileInterval := time.Second * 60
	config, _ := kubeutil.GetKubeConfig()
	client, _ := rspclient.NewForConfig(config)

	return &RSPLoader{
		defaultProfileInterval: defaultProfileInterval,
		Client:                 client,
	}
}

func (self *RSPLoader) GetData(doK8sApiCall bool) ([]rspapi.ResourceSigningProfile, bool) {
	reloaded := false
	if len(self.Data) == 0 {
		reloaded = self.Load(doK8sApiCall)
	}
	return self.Data, reloaded
}

func (self *RSPLoader) Load(doK8sApiCall bool) bool {
	var err error
	var list1 *rspapi.ResourceSigningProfileList
	var keyName string
	reloaded := false

	keyName = "RSPLoader/list"
	if cached := cache.GetString(keyName); cached == "" && doK8sApiCall {
		list1, err = self.Client.ResourceSigningProfiles().List(context.Background(), metav1.ListOptions{})
		if err != nil {
			logger.Error("failed to get ResourceSigningProfile:", err)
			return false
		}
		reloaded = true
		logger.Debug("ResourceSigningProfile reloaded.")
		if len(list1.Items) > 0 {
			tmp, _ := json.Marshal(list1)
			cache.SetString(keyName, string(tmp), &(self.defaultProfileInterval))
		}
	} else if cached != "" {
		err = json.Unmarshal([]byte(cached), &list1)
		if err != nil {
			logger.Error("failed to Unmarshal cached ResourceSigningProfile:", err)
			return false
		}
	}
	data := []rspapi.ResourceSigningProfile{}
	if list1 != nil {
		for _, d := range list1.Items {
			data = append(data, d)
		}
	}
	self.Data = data
	return reloaded
}

func (self *RSPLoader) UpdateStatus(rsp *rspapi.ResourceSigningProfile, reqc *common.RequestContext, resc *common.ResourceContext, errMsg string) error {
	rspName := rsp.GetName()
	rspOrg, err := self.Client.ResourceSigningProfiles().Get(context.Background(), rspName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	req := common.NewRequestFromReqContext(reqc)
	rspNew := rspOrg.UpdateStatus(req, errMsg)

	_, err = self.Client.ResourceSigningProfiles().Update(context.Background(), rspNew, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func (self *RSPLoader) ClearCache() {
	cache.Unset("RSPLoader/list")
}
