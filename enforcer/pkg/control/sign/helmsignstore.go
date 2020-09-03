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
	pgp "github.com/IBM/integrity-enforcer/enforcer/pkg/sign"
	pkix "github.com/IBM/integrity-enforcer/enforcer/pkg/sign/pkix"
)

type HelmSignStore struct {
	config *HelmSignStoreConfig
}

type HelmSignStoreConfig struct {
	VerifyType   VerifyType
	ChartDir     string
	ChartRepo    string
	KeyringPath  string
	CertPoolPath string
}

func NewHelmSignStore(ssconfig *config.SignStoreConfig) *HelmSignStore {
	return &HelmSignStore{
		config: &HelmSignStoreConfig{
			VerifyType:   VerifyType(ssconfig.VerifyType),
			ChartDir:     ssconfig.ChartDir,
			ChartRepo:    ssconfig.ChartRepo,
			KeyringPath:  ssconfig.KeyringPath,
			CertPoolPath: ssconfig.CertPoolPath,
		},
	}
}

func (self *HelmSignStore) GetVerifyType() VerifyType {
	return self.config.VerifyType
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
		// pkgInfo, err := helm.GetPackageInfo(rsecBytes, self.config.ChartRepo, self.config.ChartDir)
		// if err == nil {
		// 	fPath := pkgInfo.Package.FilePath
		// 	pPath := pkgInfo.Package.ProvPath
		// 	vSig := pkgInfo.Values.Signature
		// 	vMsg := pkgInfo.Values.Message
		// 	eCfg := pkgInfo.Values.EmptyConfig
		// 	return &ResourceSignature{
		// 		SignType:    SignatureTypeHelm,
		// 		keyringPath: self.config.KeyringPath,
		// 		data:        map[string]string{"pkgFilePath": fPath, "pkgProvPath": pPath, "valMessage": vMsg, "valSignature": vSig},
		// 		option:      map[string]bool{"emptyConfig": eCfg},
		// 	}
		// } else {
		// 	logger.Error(fmt.Sprintf("Error occured in get helm package info from release secret; %s", err.Error()))
		// 	return nil
		// }

		hrmSigs, err := helm.GetHelmReleaseMetadata(rsecBytes)
		if err == nil {
			message := hrmSigs[0]
			signature := hrmSigs[1]
			certificate := hrmSigs[2]
			rls := hrmSigs[3]
			hrm := hrmSigs[4]
			eCfg := true
			return &ResourceSignature{
				SignType:     SignatureTypeHelm,
				keyringPath:  self.config.KeyringPath,
				certPoolPath: self.config.CertPoolPath,
				data:         map[string]string{"message": message, "signature": signature, "certificate": certificate, "releaseSecret": rls, "helmReleaseMetadata": hrm},
				option:       map[string]bool{"emptyConfig": eCfg, "matchRequired": true},
			}
		} else {
			logger.Error(fmt.Sprintf("Error occured in getting signature from helm release metadata; %s", err.Error()))
			return nil
		}
	}
	return nil

}

type HelmVerifier struct {
	VerifyType VerifyType
	Namespace  string
}

func (self *HelmVerifier) Verify(sig *ResourceSignature, reqc *common.ReqContext) (*SigVerifyResult, error) {
	var vcerr *common.CheckError
	var vsinfo *common.SignerInfo
	var retErr error

	if sig.option["matchRequired"] {
		rls, _ := sig.data["releaseSecret"]
		hrm, _ := sig.data["helmReleaseMetadata"]
		matched := helm.MatchReleaseSecret(rls, hrm)
		if !matched {
			return &SigVerifyResult{
				Error: &common.CheckError{
					Msg:    "HelmReleaseMetadata is not identical with the release secret",
					Reason: "HelmReleaseMetadata is not identical with the release secret",
					Error:  nil,
				},
				Signer: nil,
			}, nil
		}
	}

	if self.VerifyType == VerifyTypePGP {
		message := sig.data["message"]
		signature := sig.data["signature"]
		ok, reasonFail, signer, err := pgp.VerifySignature(sig.keyringPath, message, signature)
		if err != nil {
			vcerr = &common.CheckError{
				Msg:    "Error occured in signature verification",
				Reason: reasonFail,
				Error:  err,
			}
			vsinfo = nil
			retErr = err
		} else if ok {
			vcerr = nil
			vsinfo = &common.SignerInfo{
				Email:   signer.Email,
				Name:    signer.Name,
				Comment: signer.Comment,
			}
			retErr = nil
		} else {
			vcerr = &common.CheckError{
				Msg:    "Failed to verify signature",
				Reason: reasonFail,
				Error:  nil,
			}
			vsinfo = nil
			retErr = nil
		}

	} else if self.VerifyType == VerifyTypeX509 {
		certificate := []byte(sig.data["certificate"])
		certOk, reasonFail, err := pkix.VerifyCertificate(certificate, sig.certPoolPath)
		if err != nil {
			vcerr = &common.CheckError{
				Msg:    "Error occured in certificate verification",
				Reason: reasonFail,
				Error:  err,
			}
			vsinfo = nil
			retErr = err
		} else if !certOk {
			vcerr = &common.CheckError{
				Msg:    "Failed to verify certificate",
				Reason: reasonFail,
				Error:  nil,
			}
			vsinfo = nil
			retErr = nil
		} else {
			cert, err := pkix.ParseCertificate(certificate)
			if err != nil {
				logger.Error("Failed to parse certificate; ", err)
			}
			pubKeyBytes, err := pkix.GetPublicKeyFromCertificate(certificate)
			if err != nil {
				logger.Error("Failed to get public key from certificate; ", err)
			}
			message := []byte(sig.data["message"])
			signature := []byte(sig.data["signature"])
			sigOk, reasonFail, err := pkix.VerifySignature(message, signature, pubKeyBytes)
			if err != nil {
				vcerr = &common.CheckError{
					Msg:    "Error occured in signature verification",
					Reason: reasonFail,
					Error:  err,
				}
				vsinfo = nil
				retErr = err
			} else if sigOk {
				vcerr = nil
				vsinfo = common.NewSignerInfoFromCert(cert)
				retErr = nil
			} else {
				vcerr = &common.CheckError{
					Msg:    "Failed to verify signature",
					Reason: reasonFail,
					Error:  nil,
				}
				vsinfo = nil
				retErr = nil
			}
		}
	} else {
		errMsg := fmt.Sprintf("Unknown VerifyType is specified; VerifyType: %s", string(self.VerifyType))
		vcerr = &common.CheckError{
			Msg:    errMsg,
			Reason: errMsg,
			Error:  nil,
		}
		vsinfo = nil
		retErr = nil
	}

	svresult := &SigVerifyResult{
		Error:  vcerr,
		Signer: vsinfo,
	}
	return svresult, retErr

}
