package sign

import (
	"fmt"

	"github.com/IBM/integrity-enforcer/shield/pkg/common"
)

type Verifier struct {
	verifierFunc VerifierFunc
	keyPathList  []string
	sigFrom      string
}

// VerifierFunc type is just an alias of verifier function type.
// Function should be implemented for each verification type like gpg, x509 and etc.
type VerifierFunc func(message, signature, certificate []byte, path string) (bool, *common.SignerInfo, string, error)

// NewVerifier create Verifier instance. This object is used as a wrapper of verifierFunc.
func NewVerifier(verifierFunc VerifierFunc, pathList []string, sigFrom string) *Verifier {
	return &Verifier{
		keyPathList:  pathList,
		verifierFunc: verifierFunc,
		sigFrom:      sigFrom,
	}
}

// Verify() calls verifierFunc and create Integrity Shield error object and signer info object
func (self *Verifier) Verify(message, signature, certificate []byte) (*common.CheckError, *common.SignerInfo, []string) {
	var sumErr *common.CheckError
	var sumSig *common.SignerInfo

	verifiedKeyPathList := []string{}
	for _, keyPath := range self.keyPathList {
		ok, signer, reasonFail, err := self.verifierFunc(message, signature, certificate, keyPath)
		if err != nil {
			sumErr = &common.CheckError{
				Msg:    fmt.Sprintf("Error occured while verifying signature in %s", self.sigFrom),
				Reason: reasonFail,
				Error:  err,
			}
			return sumErr, nil, []string{}
		} else if ok {
			sumSig = signer
			verifiedKeyPathList = append(verifiedKeyPathList, keyPath)
		} else {
			reasonFail = fmt.Sprintf("Failed to verify signature in %s; %s", self.sigFrom, reasonFail)
			sumErr = &common.CheckError{
				Msg:    reasonFail,
				Reason: reasonFail,
				Error:  nil,
			}
			sumSig = signer
		}
	}
	return sumErr, sumSig, verifiedKeyPathList
}

func (self *Verifier) HasAnyKey() bool {
	return len(self.keyPathList) > 0
}
