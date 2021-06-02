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
	rsigapi "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesignature/v1alpha1"

	common "github.com/IBM/integrity-enforcer/shield/pkg/common"
)

/**********************************************

				RunData

***********************************************/

type RunData struct {
	ResSigList *rsigapi.ResourceSignatureList `json:"resSigList,omitempty"`

	loader *Loader `json:"-"`
}

func (self *RunData) GetResSigList(resc *common.ResourceContext) *rsigapi.ResourceSignatureList {
	if self.ResSigList == nil && self.loader != nil {
		self.ResSigList = self.loader.ResourceSignature.GetData(resc, true)
	}
	return self.ResSigList
}
