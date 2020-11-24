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
	"encoding/json"
	"fmt"
	"time"

	rspapi "github.com/IBM/integrity-enforcer/verifier/pkg/apis/resourcesigningprofile/v1alpha1"
	rspclient "github.com/IBM/integrity-enforcer/verifier/pkg/client/resourcesigningprofile/clientset/versioned/typed/resourcesigningprofile/v1alpha1"
	common "github.com/IBM/integrity-enforcer/verifier/pkg/common/common"
	profile "github.com/IBM/integrity-enforcer/verifier/pkg/common/profile"
	cache "github.com/IBM/integrity-enforcer/verifier/pkg/util/cache"

	logger "github.com/IBM/integrity-enforcer/verifier/pkg/util/logger"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/rest"
)

// ResourceSigningProfile

type RSPLoader struct {
	verifierNamespace      string
	profileNamespace       string
	requestNamespace       string
	commonProfile          *rspapi.ResourceSigningProfileSpec
	defaultProfileInterval time.Duration

	Client *rspclient.ApisV1alpha1Client
	Data   []rspapi.ResourceSigningProfile
}

func NewRSPLoader(verifierNamespace, profileNamespace, requestNamespace string, commonProfile *rspapi.ResourceSigningProfileSpec) *RSPLoader {
	defaultProfileInterval := time.Second * 60
	config, _ := rest.InClusterConfig()
	client, _ := rspclient.NewForConfig(config)

	return &RSPLoader{
		verifierNamespace:      verifierNamespace,
		profileNamespace:       profileNamespace,
		requestNamespace:       requestNamespace,
		commonProfile:          commonProfile,
		defaultProfileInterval: defaultProfileInterval,
		Client:                 client,
	}
}

func (self *RSPLoader) GetData() []rspapi.ResourceSigningProfile {
	if len(self.Data) == 0 {
		self.Load()
	}
	return self.Data
}

func (self *RSPLoader) Load() {
	var err error
	var list1, list2, list3 *rspapi.ResourceSigningProfileList
	var keyName string

	keyName = fmt.Sprintf("RSPLoader/%s/list", self.verifierNamespace)
	if cached := cache.GetString(keyName); cached == "" {
		list1, err = self.Client.ResourceSigningProfiles(self.verifierNamespace).List(context.Background(), metav1.ListOptions{})
		if err != nil {
			logger.Error("failed to get ResourceSigningProfile:", err)
			return
		}
		logger.Debug("ResourceSigningProfile reloaded.")
		if len(list1.Items) > 0 {
			tmp, _ := json.Marshal(list1)
			cache.SetString(keyName, string(tmp), &(self.defaultProfileInterval))
		}
	} else {
		err = json.Unmarshal([]byte(cached), &list1)
		if err != nil {
			logger.Error("failed to Unmarshal cached ResourceSigningProfile:", err)
			return
		}
	}

	keyName = fmt.Sprintf("RSPLoader/%s/list", self.profileNamespace)
	if cached := cache.GetString(keyName); cached == "" {
		list2, err = self.Client.ResourceSigningProfiles(self.profileNamespace).List(context.Background(), metav1.ListOptions{})
		if err != nil {
			logger.Error("failed to get ResourceSigningProfile:", err)
			return
		}
		logger.Debug("ResourceSigningProfile reloaded.")
		if len(list2.Items) > 0 {
			tmp, _ := json.Marshal(list2)
			cache.SetString(keyName, string(tmp), &(self.defaultProfileInterval))
		}
	} else {
		err = json.Unmarshal([]byte(cached), &list2)
		if err != nil {
			logger.Error("failed to Unmarshal cached ResourceSigningProfile:", err)
			return
		}
	}

	keyName = fmt.Sprintf("RSPLoader/%s/list", self.requestNamespace)
	if cached := cache.GetString(keyName); cached == "" {
		list3, err = self.Client.ResourceSigningProfiles(self.requestNamespace).List(context.Background(), metav1.ListOptions{})
		if err != nil {
			logger.Error("failed to get ResourceSigningProfile:", err)
			return
		}
		logger.Debug("ResourceSigningProfile reloaded.")
		if len(list3.Items) > 0 {
			tmp, _ := json.Marshal(list3)
			cache.SetString(keyName, string(tmp), &(self.defaultProfileInterval))
		}
	} else {
		err = json.Unmarshal([]byte(cached), &list3)
		if err != nil {
			logger.Error("failed to Unmarshal cached ResourceSigningProfile:", err)
			return
		}
	}
	data := []rspapi.ResourceSigningProfile{}
	for _, d := range list1.Items {
		data = append(data, d)
	}
	for _, d := range list2.Items {
		data = append(data, d)
	}
	for _, d := range list3.Items {
		data = append(data, d)
	}
	self.Data = data
	return
}

func (self *RSPLoader) GetByReferences(refs []*v1.ObjectReference) []rspapi.ResourceSigningProfile {
	data := []rspapi.ResourceSigningProfile{}
	for _, ref := range refs {
		d, err := self.Client.ResourceSigningProfiles(ref.Namespace).Get(context.Background(), ref.Name, metav1.GetOptions{})
		if err != nil {
			logger.Error(err)
		} else {
			data = append(data, *d)
		}
	}
	// add empty RSP if there is no matched reference, to enable default RSP even in the case
	if len(data) == 0 {
		emptyProfile := rspapi.ResourceSigningProfile{}
		data = []rspapi.ResourceSigningProfile{
			emptyProfile,
		}
	}
	data, err := self.MergeDefaultProfiles(data)
	if err != nil {
		logger.Error(err)
	}
	return data
}

func (self *RSPLoader) MergeDefaultProfiles(data []rspapi.ResourceSigningProfile) ([]rspapi.ResourceSigningProfile, error) {
	dp, err := self.GetDefaultProfile()
	if err != nil {
		logger.Error(err)
	} else {
		for i, d := range data {
			data[i] = d.Merge(dp)
		}
	}
	return data, nil
}

func (self *RSPLoader) GetDefaultProfile() (rspapi.ResourceSigningProfile, error) {
	rsp := rspapi.ResourceSigningProfile{}
	rsp.Spec = *(self.commonProfile)
	return rsp, nil
}

func (self *RSPLoader) UpdateStatus(sProfile profile.SigningProfile, reqc *common.ReqContext, errMsg string) error {
	rsp, ok := sProfile.(rspapi.ResourceSigningProfile)
	if !ok {
		logger.Warn(fmt.Sprintf("The profile is not an instance of ResourceSigningProfile but one of %T; skip updating status.", sProfile))
		return nil
	}
	rspNamespace := rsp.GetNamespace()
	rspName := rsp.GetName()
	rspOrg, err := self.Client.ResourceSigningProfiles(rspNamespace).Get(context.Background(), rspName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	req := profile.NewRequestFromReqContext(reqc)
	rspNew := rspOrg.UpdateStatus(req, errMsg)

	_, err = self.Client.ResourceSigningProfiles(rspNamespace).Update(context.Background(), rspNew, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
}
