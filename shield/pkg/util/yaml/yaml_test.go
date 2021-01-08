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

package yaml

import (
	"testing"
)

const testMessage = "YXBpVmVyc2lvbjogdjEKa2luZDogU2VydmljZQptZXRhZGF0YToKICBuYW1lOiB0ZXN0LW11bHRpMi1zZXJ2aWNlCnNwZWM6CiAgdHlwZTogTG9hZEJhbGFuY2VyCiAgc2VsZWN0b3I6CiAgICBhcHA6IGhpcm8tdGVzdC1hcHAKICBwb3J0czoKICAtIHByb3RvY29sOiBUQ1AKICAgIHBvcnQ6IDgwCiAgICB0YXJnZXRQb3J0OiA5Mzc2Ci0tLQphcGlWZXJzaW9uOiB2MQpraW5kOiBDb25maWdNYXAKbWV0YWRhdGE6CiAgbmFtZTogc2FtcGxlLWNtCmRhdGE6CiAga2V5MTogdmFsMQogIGtleTI6IHZhbDIK"

func TestFindSingleYaml(t *testing.T) {
	ok, _ := FindSingleYaml([]byte(testMessage), "v1", "ConfigMap", "sample-cm", "secure-ns")
	if !ok {
		t.Error("Failed to test FindSingleYaml()")
	}
}
