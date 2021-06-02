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
	"encoding/json"
)

/**********************************************

				DecisionResult

***********************************************/

type DecisionResult struct {
	Type            DecisionType `json:"type,omitempty"`
	Verified        bool         `json:"verified,omitempty"`
	IShieldResource bool         `json:"ishieldResource,omitempty"`
	ReasonCode      int          `json:"reasonCode,omitempty"`
	Message         string       `json:"message,omitempty"`
}

func UndeterminedDecision() *DecisionResult {
	return &DecisionResult{Type: DecisionUndetermined}
}

func (self *DecisionResult) String() string {
	drB, _ := json.Marshal(self)
	return string(drB)
}

func (self *DecisionResult) IsAllowed() bool {
	return self.Type == DecisionAllow
}

func (self *DecisionResult) IsDenied() bool {
	return self.Type == DecisionDeny
}

func (self *DecisionResult) IsUndetermined() bool {
	return self.Type == DecisionUndetermined
}

func (self *DecisionResult) IsErrorOccurred() bool {
	return self.Type == DecisionError
}
