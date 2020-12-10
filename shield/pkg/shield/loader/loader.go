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
	config "github.com/IBM/integrity-enforcer/shield/pkg/shield/config"
)

/**********************************************

				Loader

***********************************************/

type Loader struct {
	SignPolicy        *SignPolicyLoader
	RSP               *RSPLoader
	Namespace         *NamespaceLoader
	ResourceSignature *ResSigLoader
}

func NewLoader(cfg *config.ShieldConfig, reqNamespace string) *Loader {
	shieldNamespace := cfg.Namespace
	requestNamespace := reqNamespace
	signatureNamespace := cfg.SignatureNamespace // for non-existing namespace / cluster scope
	profileNamespace := cfg.ProfileNamespace     // for non-existing namespace / cluster scope
	loader := &Loader{
		SignPolicy:        NewSignPolicyLoader(shieldNamespace),
		RSP:               NewRSPLoader(shieldNamespace, profileNamespace, requestNamespace, cfg.CommonProfile),
		Namespace:         NewNamespaceLoader(),
		ResourceSignature: NewResSigLoader(signatureNamespace, requestNamespace),
	}
	return loader
}
