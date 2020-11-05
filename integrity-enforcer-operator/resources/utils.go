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

package resources

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"reflect"
	"strings"

	apiv1alpha1 "github.com/IBM/integrity-enforcer/integrity-enforcer-operator/api/v1alpha1"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/ghodss/yaml"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
)

var int420Var int32 = 420

const saTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
const defaultIECRYamlPath = "/resources/default-ie-cr.yaml"

func SecretVolume(name, secretName string) v1.Volume {

	return v1.Volume{
		Name: name,
		VolumeSource: v1.VolumeSource{
			Secret: &v1.SecretVolumeSource{
				SecretName:  secretName,
				DefaultMode: &int420Var,
			},
		},
	}

}

func EmptyDirVolume(name string) v1.Volume {

	return v1.Volume{
		Name: name,
		VolumeSource: v1.VolumeSource{
			EmptyDir: &v1.EmptyDirVolumeSource{},
		},
	}
}

func getOperatorServiceAccount() string {
	tokenBytes, err := ioutil.ReadFile(saTokenPath)
	if err != nil {
		return ""
	}
	tokenString := string(tokenBytes)
	claimSeg := strings.Split(tokenString, ".")[1]

	claimBytes, err := jwt.DecodeSegment(claimSeg)
	if err != nil {
		fmt.Println(err.Error())
		return ""
	}
	var claimMap map[string]string
	err = json.Unmarshal(claimBytes, &claimMap)
	if err != nil {
		fmt.Println(err.Error())
		return ""
	}
	saUser, ok := claimMap["sub"]
	if !ok {
		return ""
	}
	return saUser
}

func MergeDefaultIntegrityEnforcerCR(cr *apiv1alpha1.IntegrityEnforcer, srcYamlPath string) *apiv1alpha1.IntegrityEnforcer {
	if srcYamlPath == "" {
		srcYamlPath = defaultIECRYamlPath
	}
	deafultCRBytes, _ := ioutil.ReadFile(srcYamlPath)
	defaultCRJsonBytes, err := yaml.YAMLToJSON(deafultCRBytes)
	if err != nil {
		fmt.Println("failed to convert yaml2json; " + err.Error())
		return cr
	}

	crJsonBytes, err := json.Marshal(cr)
	if err != nil {
		fmt.Println("failed to convert instance 2 yaml; " + err.Error())
		return cr
	}

	crType := reflect.TypeOf(cr)
	if crType.Kind() == reflect.Ptr {
		crType = crType.Elem()
	}
	dataStruct := strategicpatch.PatchMetaFromStruct{T: crType}

	mergedCRBytes, err := strategicpatch.StrategicMergePatchUsingLookupPatchMeta(defaultCRJsonBytes, crJsonBytes, dataStruct)
	if err != nil {
		fmt.Println("failed to StrategicMergePatch; " + err.Error())
		return cr
	}
	var mergedCR *apiv1alpha1.IntegrityEnforcer
	err = json.Unmarshal(mergedCRBytes, &mergedCR)
	if err != nil {
		fmt.Println("failed to Unmarshal; " + err.Error())
		return cr
	}
	return mergedCR
}
