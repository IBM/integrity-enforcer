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
	"os"
	"reflect"
	"strings"
	"testing"

	apiv1alpha1 "github.com/IBM/integrity-enforcer/integrity-shield-operator/api/v1alpha1"
	"github.com/IBM/integrity-enforcer/shield/pkg/util/mapnode"
	"github.com/ghodss/yaml"
	"github.com/google/go-cmp/cmp"
)

const defaultIShieldCRPath = "./default-ishield-cr.yaml"
const sampleIShieldCRPath = "../config/samples/apis_v1alpha1_integrityshield.yaml"

var commonProfilePathList = []string{"./common-profiles/kubernetes-profile.yaml", "./common-profiles/openshift-profile.yaml", "./common-profiles/others-profile.yaml"}

func loadTestInstance(t *testing.T) *apiv1alpha1.IntegrityShield {
	iecrYamlBytes, err := ioutil.ReadFile(sampleIShieldCRPath)
	if err != nil {
		t.Errorf(err.Error())
	}
	var iecr *apiv1alpha1.IntegrityShield
	err = yaml.Unmarshal(iecrYamlBytes, &iecr)
	if err != nil {
		t.Errorf(err.Error())
	}
	ishieldcr := MergeDefaultIntegrityShieldCR(iecr, defaultIShieldCRPath)
	_, err = json.Marshal(iecr)
	if err != nil {
		t.Errorf(err.Error())
	}

	err = writeOnFile("./testdata/integrityShieldCR.yaml", ishieldcr)
	if err != nil {
		t.Errorf(err.Error())
	}

	// t.Log(string(iecrJsonBytes))
	// instance.Namespace = "testns"

	return ishieldcr

}

func writeOnFile(fileName string, data interface{}) error {
	buf, err := yaml.Marshal(data)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(fileName, buf, os.ModePerm)
	if err != nil {
		return err
	}
	return nil
}

func testObjAndYaml(t *testing.T, obj interface{}, yamlPath string) {

	// err := writeOnFile(yamlPath, obj)
	// if err != nil {
	// 	t.Errorf(err.Error())
	// 	return
	// }

	builtJsonB, _ := json.Marshal(obj)
	builtNode, err := mapnode.NewFromBytes(builtJsonB)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	goodYamlB, err := ioutil.ReadFile(yamlPath)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	goodNode, err := mapnode.NewFromYamlBytes(goodYamlB)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	if builtNode == nil {
		t.Errorf("buildNode is nil")
		return
	}

	if goodNode == nil {
		t.Errorf("goodNode is nil")
		return
	}

	dr := builtNode.Diff(goodNode)
	if dr != nil && dr.Size() > 0 {
		t.Errorf("Diff found between object generated by code and testdata; [before: generated object, after: testdata]")
		for _, d := range dr.Items {
			t.Errorf(fmt.Sprintf("%s", d))
			before := d.Values["before"]
			after := d.Values["after"]
			if before != nil && reflect.TypeOf(before).Kind() == reflect.String {
				beforeStr := before.(string)
				afterStr := ""
				if after != nil {
					afterStr = after.(string)
				}
				diffstr := cmp.Diff(strings.Split(beforeStr, "\n"), strings.Split(afterStr, "\n"))
				t.Errorf(fmt.Sprintf("\tdetail: %s", diffstr))
			}
		}
	}
}

func TestShieldConfigCRD(t *testing.T) {
	instance := loadTestInstance(t)
	obj := BuildShieldConfigCRD(instance)
	yamlPath := "./testdata/shieldConfigCRD.yaml"
	testObjAndYaml(t, obj, yamlPath)
}

func TestResourceSignatureCRD(t *testing.T) {
	instance := loadTestInstance(t)
	obj := BuildResourceSignatureCRD(instance)
	yamlPath := "./testdata/resourceSignatureCRD.yaml"
	testObjAndYaml(t, obj, yamlPath)
}
func TestResourceSigningProfileCRD(t *testing.T) {
	instance := loadTestInstance(t)
	obj := BuildResourceSigningProfileCRD(instance)
	yamlPath := "./testdata/resourceSigningProfileCRD.yaml"
	testObjAndYaml(t, obj, yamlPath)
}
func TestShieldConfigCR(t *testing.T) {
	instance := loadTestInstance(t)
	obj := BuildShieldConfigForIShield(instance, nil, commonProfilePathList)
	yamlPath := "./testdata/shieldConfigForIShield.yaml"
	testObjAndYaml(t, obj, yamlPath)
}

func TestResourceSigningProfileCR(t *testing.T) {
	instance := loadTestInstance(t)
	if len(instance.Spec.ResourceSigningProfiles) > 0 {
		for _, prof := range instance.Spec.ResourceSigningProfiles {
			obj := BuildResourceSigningProfileForIShield(instance, prof)
			yamlPath := "./testdata/resourceSigningProfileForIShield.yaml"
			testObjAndYaml(t, obj, yamlPath)
			break
		}
	}
}

// IShieldAdmin RBAC

func TestClusterRoleBindingForIShieldAdmin(t *testing.T) {
	instance := loadTestInstance(t)
	obj := BuildClusterRoleBindingForIShieldAdmin(instance)
	yamlPath := "./testdata/clusterRoleBindingForIShieldAdmin.yaml"
	testObjAndYaml(t, obj, yamlPath)
}

func TestRoleBindingForIShieldAdmin(t *testing.T) {
	instance := loadTestInstance(t)
	obj := BuildRoleBindingForIShieldAdmin(instance)
	yamlPath := "./testdata/roleBindingForIShieldAdmin.yaml"
	testObjAndYaml(t, obj, yamlPath)
}
func TestRoleForIShieldAdmin(t *testing.T) {
	instance := loadTestInstance(t)
	obj := BuildRoleForIShieldAdmin(instance)
	yamlPath := "./testdata/roleForIShieldAdmin.yaml"
	testObjAndYaml(t, obj, yamlPath)
}
func TestClusterRoleForIShieldAdmin(t *testing.T) {
	instance := loadTestInstance(t)
	obj := BuildClusterRoleForIShieldAdmin(instance)
	yamlPath := "./testdata/clusterRoleForIShieldAdmin.yaml"
	testObjAndYaml(t, obj, yamlPath)
}

//IShield RBAC

func TestClusterRoleBindingForIShield(t *testing.T) {
	instance := loadTestInstance(t)
	obj := BuildClusterRoleBindingForIShield(instance)
	yamlPath := "./testdata/clusterRoleBindingForIShield.yaml"
	testObjAndYaml(t, obj, yamlPath)
}

func TestRoleBindingForIShield(t *testing.T) {
	instance := loadTestInstance(t)
	obj := BuildRoleBindingForIShield(instance)
	yamlPath := "./testdata/roleBindingForIShield.yaml"
	testObjAndYaml(t, obj, yamlPath)
}
func TestRoleForIShield(t *testing.T) {
	instance := loadTestInstance(t)
	obj := BuildRoleForIShield(instance)
	yamlPath := "./testdata/roleForIShield.yaml"
	testObjAndYaml(t, obj, yamlPath)
}
func TestClusterRoleForIShield(t *testing.T) {
	instance := loadTestInstance(t)
	obj := BuildClusterRoleForIShield(instance)
	yamlPath := "./testdata/clusterRoleForIShield.yaml"
	testObjAndYaml(t, obj, yamlPath)
}

func TestPodSecurityPolicy(t *testing.T) {
	instance := loadTestInstance(t)
	obj := BuildPodSecurityPolicy(instance)
	yamlPath := "./testdata/podSecurityPolicy.yaml"
	testObjAndYaml(t, obj, yamlPath)
}
func TestRegKeySecret(t *testing.T) {
	instance := loadTestInstance(t)
	obj := BuildRegKeySecretForIShield(instance)
	yamlPath := "./testdata/regKeySecretForIShield.yaml"
	testObjAndYaml(t, obj, yamlPath)
}
func TestTlsSecret(t *testing.T) {
	instance := loadTestInstance(t)
	obj := BuildTlsSecretForIShield(instance)
	yamlPath := "./testdata/tlsSecretForIShield.yaml"
	testObjAndYaml(t, obj, yamlPath)
}

func TestDeploymentForIShield(t *testing.T) {
	instance := loadTestInstance(t)
	obj := BuildDeploymentForIShield(instance)
	yamlPath := "./testdata/deploymentForIShield.yaml"
	testObjAndYaml(t, obj, yamlPath)
}
func TestServiceForIShield(t *testing.T) {
	instance := loadTestInstance(t)
	obj := BuildServiceForIShield(instance)
	yamlPath := "./testdata/serviceForIShield.yaml"
	testObjAndYaml(t, obj, yamlPath)
}
func TestMutatingWebhookConfigurationForIShield(t *testing.T) {
	instance := loadTestInstance(t)
	obj := BuildMutatingWebhookConfigurationForIShield(instance)
	yamlPath := "./testdata/mutatingWebhookConfigurationForIShield.yaml"
	testObjAndYaml(t, obj, yamlPath)
}
