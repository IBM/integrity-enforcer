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

package common

import (
	"strconv"
	"strings"

	"github.com/IBM/integrity-enforcer/enforcer/pkg/kubeutil"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1cli "k8s.io/client-go/kubernetes/typed/core/v1"
)

func (rc *ReqContext) IsVerifiedServiceAccount() bool {
	// get sa
	sa, err := GetServiceAccount(rc)
	if err != nil || sa == nil {
		return false
	}

	// sa has integrity verified
	if rc.Namespace != sa.ObjectMeta.Namespace {
		return false
	}
	if s, ok := sa.Annotations["integrityVerified"]; ok {
		if b, err := strconv.ParseBool(s); err != nil {
			return false
		} else {
			return b
		}
	}
	return false
}

func GetServiceAccount(rc *ReqContext) (*v1.ServiceAccount, error) {

	if rc.ServiceAccount != nil {
		return rc.ServiceAccount, nil
	}

	if !strings.HasPrefix(rc.UserName, "system:") {
		return nil, nil
	}

	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		return nil, err
	}
	v1client := v1cli.NewForConfigOrDie(config)

	name := strings.Split(rc.UserName, ":")
	saName := name[len(name)-1]
	namespace := name[len(name)-2]

	serviceAccount, err := v1client.ServiceAccounts(namespace).Get(saName, metav1.GetOptions{})
	rc.ServiceAccount = serviceAccount
	if err != nil {
		return nil, err
	}
	return rc.ServiceAccount, nil
}
