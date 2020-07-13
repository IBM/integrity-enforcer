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

package sign

import (
	"fmt"

	config "github.com/IBM/integrity-enforcer/enforcer/pkg/config"
	common "github.com/IBM/integrity-enforcer/enforcer/pkg/control/common"
	helm "github.com/IBM/integrity-enforcer/enforcer/pkg/helm"
	logger "github.com/IBM/integrity-enforcer/enforcer/pkg/logger"
)

type HelmSignStore struct {
	config *HelmSignStoreConfig
}

type HelmSignStoreConfig struct {
	ChartDir    string
	ChartRepo   string
	KeyringPath string
}

func NewHelmSignStore(ssconfig *config.SignStoreConfig) *HelmSignStore {
	return &HelmSignStore{
		config: &HelmSignStoreConfig{
			ChartDir:    ssconfig.ChartDir,
			ChartRepo:   ssconfig.ChartRepo,
			KeyringPath: ssconfig.KeyringPath,
		},
	}
}

func (self *HelmSignStore) GetResourceSignature(ref *common.ResourceRef, reqc *common.ReqContext) *ResourceSignature {
	if !reqc.IsCreateRequest() && !reqc.IsUpdateRequest() {
		return nil
	}

	rsecBytes, err := helm.FindReleaseSecret(reqc.Namespace, reqc.Kind, reqc.Name, reqc.RawObject)
	if err != nil {
		logger.Error(fmt.Sprintf("Error occured in finding helm release secret; %s", err.Error()))
		return nil
	}
	if rsecBytes != nil {
		pkgInfo, err := helm.GetPackageInfo(rsecBytes, self.config.ChartRepo, self.config.ChartDir)
		if err == nil {
			fPath := pkgInfo.Package.FilePath
			pPath := pkgInfo.Package.ProvPath
			vSig := pkgInfo.Values.Signature
			vMsg := pkgInfo.Values.Message
			eCfg := pkgInfo.Values.EmptyConfig
			return &ResourceSignature{
				SignType:    SignatureTypeHelm,
				keyringPath: self.config.KeyringPath,
				data:        map[string]string{"pkgFilePath": fPath, "pkgProvPath": pPath, "valMessage": vMsg, "valSignature": vSig},
				option:      map[string]bool{"emptyConfig": eCfg},
			}
		} else {
			logger.Error(fmt.Sprintf("Error occured in get helm package info from release secret; %s", err.Error()))
			return nil
		}
	}
	return nil

}

type HelmVerifier struct {
	Namespace string
}

func (self *HelmVerifier) Verify(sig *ResourceSignature, reqc *common.ReqContext) (*SigVerifyResult, error) {
	var vcerr *common.CheckError
	var vsinfo *common.SignerInfo
	var retErr error

	signer, err := helm.VerifyPackage(sig.data["pkgFilePath"], sig.data["pkgProvPath"], sig.keyringPath)
	if err != nil {
		vcerr = &common.CheckError{
			Msg:    "Failed to load keyring",
			Reason: "Failed to load keyring",
			Error:  err,
		}
		vsinfo = nil
		retErr = err
	} else if signer == nil {
		vcerr = &common.CheckError{
			Msg:    "Failed to verify Helm package; no valid signer",
			Reason: "Failed to verify Helm package; no valid signer",
			Error:  nil,
		}
		vsinfo = nil
		retErr = nil
	} else {
		vcerr = nil
		vsinfo = &common.SignerInfo{
			Email:   signer.Email,
			Name:    signer.Name,
			Comment: signer.Comment,
		}
		retErr = nil
	}

	svresult := &SigVerifyResult{
		Error:  vcerr,
		Signer: vsinfo,
	}
	return svresult, retErr
}
