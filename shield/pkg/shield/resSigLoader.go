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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/IBM/integrity-enforcer/shield/pkg/common"
	cache "github.com/IBM/integrity-enforcer/shield/pkg/util/cache"

	rsigapi "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesignature/v1alpha1"
	rsigclient "github.com/IBM/integrity-enforcer/shield/pkg/client/resourcesignature/clientset/versioned/typed/resourcesignature/v1alpha1"
	logger "github.com/IBM/integrity-enforcer/shield/pkg/util/logger"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/rest"
)

// ResourceSignature

type ResSigLoader struct {
	interval           time.Duration
	signatureNamespace string
	requestNamespace   string
	reqApiVersion      string
	reqKind            string

	Client *rsigclient.ApisV1alpha1Client
	Data   *rsigapi.ResourceSignatureList
}

func NewResSigLoader(signatureNamespace, requestNamespace string) *ResSigLoader {
	interval := time.Second * 0
	config, _ := rest.InClusterConfig()
	client, _ := rsigclient.NewForConfig(config)

	return &ResSigLoader{
		interval:           interval,
		signatureNamespace: signatureNamespace,
		requestNamespace:   requestNamespace,
		Client:             client,
	}
}

func (self *ResSigLoader) GetData(reqc *common.ReqContext, doK8sApiCall bool) *rsigapi.ResourceSignatureList {
	if self.Data == nil {
		self.Load(reqc, doK8sApiCall)
	}
	return self.Data
}

func (self *ResSigLoader) Load(reqc *common.ReqContext, doK8sApiCall bool) {
	var err error
	var list1, list2 *rsigapi.ResourceSignatureList
	var keyName string

	// For ApiVersion label, `apps_v1` is used instead of `apps/v1`, because "/" cannot be used in label value
	reqApiVersion := strings.ReplaceAll(reqc.GroupVersion(), "/", "_")
	reqKind := reqc.Kind
	labelSelector := fmt.Sprintf("%s=%s,%s=%s", common.ResSigLabelApiVer, reqApiVersion, common.ResSigLabelKind, reqKind)

	keyName = fmt.Sprintf("ResSigLoader/%s/list/%s", self.signatureNamespace, labelSelector)
	if cached := cache.GetString(keyName); cached == "" && doK8sApiCall {
		list1, err = self.Client.ResourceSignatures(self.signatureNamespace).List(context.Background(), metav1.ListOptions{LabelSelector: labelSelector})
		if err != nil {
			logger.Error("failed to get ResourceSignature:", err)
			return
		}
		logger.Debug("ResourceSignature reloaded.")
		if len(list1.Items) > 0 {
			tmp, _ := json.Marshal(list1)
			cache.SetString(keyName, string(tmp), &(self.interval))
		}
	} else if cached != "" {
		err = json.Unmarshal([]byte(cached), &list1)
		if err != nil {
			logger.Error("failed to Unmarshal cached ResourceSignature:", err)
			return
		}
	}
	keyName = fmt.Sprintf("ResSigLoader/%s/list/%s", self.requestNamespace, labelSelector)
	if cached := cache.GetString(keyName); cached == "" && doK8sApiCall {
		list2, err = self.Client.ResourceSignatures(self.requestNamespace).List(context.Background(), metav1.ListOptions{LabelSelector: labelSelector})
		if err != nil {
			logger.Error("failed to get ResourceSignature:", err)
			return
		}
		logger.Debug("ResourceSignature reloaded.")
		if len(list2.Items) > 0 {
			tmp, _ := json.Marshal(list2)
			cache.SetString(keyName, string(tmp), &(self.interval))
		}
	} else {
		err = json.Unmarshal([]byte(cached), &list2)
		if err != nil {
			logger.Error("failed to Unmarshal cached ResourceSignature:", err)
			return
		}
	}

	data := []*rsigapi.ResourceSignature{}
	if list1 != nil {
		for _, d := range list1.Items {
			data = append(data, d)
		}
	}
	if list2 != nil {
		for _, d := range list2.Items {
			data = append(data, d)
		}
	}
	sortedData := sortByTimestamp(data)
	self.Data = &rsigapi.ResourceSignatureList{Items: sortedData}
	return
}

func sortByTimestamp(items []*rsigapi.ResourceSignature) []*rsigapi.ResourceSignature {
	items2 := make([]*rsigapi.ResourceSignature, len(items))
	copy(items2, items)
	sort.Slice(items2, func(i, j int) bool {
		ti := 0
		tj := 0
		tis, ok1 := items2[i].GetLabels()[common.ResSigLabelTime]
		if ok1 {
			ti, _ = strconv.Atoi(tis)
		}
		tjs, ok2 := items2[j].GetLabels()[common.ResSigLabelTime]
		if ok2 {
			tj, _ = strconv.Atoi(tjs)
		}
		return ti > tj
	})
	return items2
}
