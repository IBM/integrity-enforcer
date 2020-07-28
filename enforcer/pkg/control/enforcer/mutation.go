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

package enforcer

import (
	common "github.com/IBM/integrity-enforcer/enforcer/pkg/control/common"
	mapnode "github.com/IBM/integrity-enforcer/enforcer/pkg/mapnode"
	policy "github.com/IBM/integrity-enforcer/enforcer/pkg/policy"
	whitelist "github.com/IBM/integrity-enforcer/enforcer/pkg/whitelist"
)

type MutationChecker interface {
	Eval(reqc *common.ReqContext, policy []policy.AllowedChangeCondition) (*common.MutationEvalResult, error)
}

type ConcreteMutationChecker struct {
	VerifiedOwners []*common.Owner
}

func (self *ConcreteMutationChecker) Eval(reqc *common.ReqContext, policy []policy.AllowedChangeCondition) (*common.MutationEvalResult, error) {

	mask := []string{
		"metadata.annotations.namespace",
		"metadata.labels.integrity-enforcer.ibm.com/resourceIntegrity",
		"metadata.labels.integrity-enforcer.ibm.com/reason",
		"metadata.annotations.sigOwnerKind",
		"metadata.annotations.sigOwnerApiVersion",
		"metadata.annotations.sigOwnerName",
		"metadata.annotations.resourceSignatureName",
		"metadata.annotations.signOwnerRefType",
		"status",
		"metadata.creationTimestamp",
		"metadata.uid",
		"metadata.generation",
	}

	maResult := &common.MutationEvalResult{
		IsMutated: false,
		Checked:   false,
	}

	var oldObj, newObj map[string]interface{}
	// oldObj from reqc.RawOldObject
	if reqc.RawOldObject == nil {
		maResult.Error = &common.CheckError{
			Reason: "no old object in request",
		}
		return maResult, nil
	}

	if v, err := mapnode.NewFromBytes(reqc.RawOldObject); err != nil || v == nil {
		maResult.Error = &common.CheckError{
			Error:  err,
			Reason: "fail to parse old object in request",
		}
		return maResult, nil
	} else {
		v = v.Mask(mask)
		oldObj = v.ToMap()
	}

	// newObj from reqc.RawObject
	if reqc.RawObject == nil {
		maResult.Error = &common.CheckError{
			Reason: "no (claimed) object in request",
		}
		return maResult, nil
	}

	if v, err := mapnode.NewFromBytes(reqc.RawObject); err != nil || v == nil {
		maResult.Error = &common.CheckError{
			Error:  err,
			Reason: "fail to parse (claimed) object in request",
		}
		return maResult, nil
	} else {
		v = v.Mask(mask)
		newObj = v.ToMap()
	}

	ma4kInput := NewMa4kInput(reqc.Namespace, reqc.Kind, reqc.Name, reqc.UserName, reqc.UserGroups, oldObj, newObj, self.VerifiedOwners)
	if mr, err := GetMAResult(ma4kInput, policy); err != nil {
		maResult.Error = &common.CheckError{
			Error:  err,
			Reason: "Error when checking mutation",
		}
		return maResult, nil
	} else {
		maResult.IsMutated = mr.IsMutated
		maResult.Diff = mr.Diff
		maResult.Filtered = mr.Filtered
		maResult.Checked = mr.Checked
		maResult.Error = &common.CheckError{
			Error:  mr.Error,
			Reason: mr.Msg,
		}
		return maResult, nil
	}

}

func NewMutationChecker(owners []*common.Owner) (MutationChecker, error) {
	return &ConcreteMutationChecker{
		VerifiedOwners: owners,
	}, nil
}

type Ma4kInput struct {
	Before       map[string]interface{} `json:"before"`
	After        map[string]interface{} `json:"after"`
	Namespace    string                 `json:"namespace"`
	UserName     string                 `json:"userName"`
	Kind         string                 `json:"kind"`
	Name         string                 `json:"name"`
	UserGroups   []string               `json:"userGroups"`
	IntegrityRef *common.ResourceRef    `json:"owner"`
}

type MAResult struct {
	IsMutated bool
	Diff      string
	Filtered  string
	Checked   bool
	Msg       string
	Error     error
}

func NewMa4kInput(namespace, kind, name, username string, usergroups []string, oldObj map[string]interface{}, newObj map[string]interface{}, owners []*common.Owner) *Ma4kInput {
	var ownerRef *common.ResourceRef
	for _, ow := range owners {
		ownerRef = ow.Ref
	}
	ma4kInput := &Ma4kInput{
		Before:       oldObj,
		After:        newObj,
		Namespace:    namespace,
		Name:         name,
		Kind:         kind,
		UserName:     username,
		UserGroups:   usergroups,
		IntegrityRef: ownerRef,
	}
	return ma4kInput
}

func MutationMessage(resourceName string, diffResult []mapnode.Difference) (msg string) {
	msg = "no mutation"
	if len(diffResult) != 0 {
		if len(diffResult) == 1 {
			diff := diffResult[0]
			msg = diff.Key + " in " + resourceName + " is mutated."
		} else {
			var mutatedKeys string
			for _, diff := range diffResult {
				if len(mutatedKeys) == 0 {
					mutatedKeys = diff.Key
				} else {
					mutatedKeys = mutatedKeys + "," + diff.Key
				}
			}
			msg = mutatedKeys + " in " + resourceName + " are mutated."
		}
	}
	return msg
}

func GetMAResult(ma4kInput *Ma4kInput, policy []policy.AllowedChangeCondition) (*MAResult, error) {
	mr := &MAResult{}
	oldObject, _ := mapnode.NewFromMap(ma4kInput.Before)
	newObject, _ := mapnode.NewFromMap(ma4kInput.After)

	// whitelist
	namespace := ma4kInput.Namespace
	name := ma4kInput.Name
	kind := ma4kInput.Kind
	username := ma4kInput.UserName
	userGroups := ma4kInput.UserGroups
	var ownerKind, ownerApiVersion, ownerName string
	if ma4kInput.IntegrityRef != nil {
		ownerKind = ma4kInput.IntegrityRef.Kind
		ownerApiVersion = ma4kInput.IntegrityRef.ApiVersion
		ownerName = ma4kInput.IntegrityRef.Name
	}

	allWhitelist := whitelist.NewEPW()
	allWhitelist.Rule = policy
	allMaskKeys := allWhitelist.GenerateMaskKeys(namespace, name, kind, username, ownerKind, ownerApiVersion, ownerName, userGroups)

	// diff
	dr := oldObject.Diff(newObject)
	//dr := maskedOldObj.Diff(maskedNewObj)

	// split diff into 2 diffs with whitelist (mc & cmc)
	filtered := &mapnode.DiffResult{}
	unfiltered := &mapnode.DiffResult{}
	if dr != nil {
		//filtered, unfiltered = dr.Filter(appMaskKeys)
		filtered, unfiltered = dr.Filter(allMaskKeys)
	}

	// make result
	if unfiltered.Size() == 0 {
		mr.IsMutated = false
		mr.Checked = true
	} else {
		mr.IsMutated = true
		mr.Checked = true
	}
	mr.Diff = unfiltered.String()
	mr.Filtered = filtered.String()
	msg := MutationMessage(ma4kInput.Name, unfiltered.Items)
	mr.Msg = msg
	return mr, nil
}
