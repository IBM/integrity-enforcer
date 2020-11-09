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
	"io/ioutil"
	"testing"

	apiv1alpha1 "github.com/IBM/integrity-enforcer/integrity-enforcer-operator/api/v1alpha1"
	"github.com/ghodss/yaml"
)

const defaultIECRPath = "./default-ie-cr.yaml"
const sampleIECRPath = "../config/samples/apis_v1alpha1_integrityenforcer.yaml"

func TestUtils(t *testing.T) {
	iecrYamlBytes, err := ioutil.ReadFile(sampleIECRPath)
	if err != nil {
		t.Error(err)
	}
	var iecr *apiv1alpha1.IntegrityEnforcer
	err = yaml.Unmarshal(iecrYamlBytes, &iecr)
	if err != nil {
		t.Error(err)
	}
	iecr = MergeDefaultIntegrityEnforcerCR(iecr, defaultIECRPath)
	iecrJsonBytes, err := json.Marshal(iecr)
	if err != nil {
		t.Error(err)
	}
	t.Log(string(iecrJsonBytes))
}
