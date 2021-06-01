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

package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	rspapi "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesigningprofile/v1alpha1"
	"github.com/IBM/integrity-enforcer/shield/pkg/common"
	sconfloder "github.com/IBM/integrity-enforcer/shield/pkg/config/loader"
	"github.com/IBM/integrity-enforcer/shield/pkg/shield"
	"github.com/IBM/integrity-enforcer/shield/pkg/util/logger"
	log "github.com/sirupsen/logrus"
	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

// const (
// 	apiBaseURLEnvKey  = "CHECKER_API_BASE_URL"
// 	defaultAPIBaseURL = "http://integrity-shield-checker:8080"
// )

// var apiBaseURL string

var config *sconfloder.Config

var rspLoader *RSPLoader
var nsLoader *NamespaceLoader
var ruletable *RuleTable

var (
	universalDeserializer = serializer.NewCodecFactory(runtime.NewScheme()).UniversalDeserializer()
)

type WebhookServer struct {
	mux               *http.ServeMux
	certPath, keyPath string
}

func init() {
	config = sconfloder.NewConfig()
	_ = config.InitShieldConfig()

	log.SetFormatter(&log.JSONFormatter{})

	logger.SetSingletonLoggerLevel(config.ShieldConfig.Log.LogLevel)
	logger.Info("Integrity Shield has been started.")

	// apiBaseURL = os.Getenv(apiBaseURLEnvKey)
	// if apiBaseURL == "" {
	// 	apiBaseURL = defaultAPIBaseURL
	// }

	rspLoader = NewRSPLoader()
	nsLoader = NewNamespaceLoader()
	rspList, _ := rspLoader.GetData(true)
	nsList, _ := nsLoader.GetData(true)

	ruletable = NewRuleTable(rspList, nsList, config.ShieldConfig.CommonProfile, config.ShieldConfig.Namespace)
	if ruletable == nil {
		logger.Fatal("Failed to initialize integrity shield rule table. Exitting...")
	}
}

// Check if any profile matches the request (this can be replaced with gatekeeper constraints matching)
func (server *WebhookServer) groupKindNamespaceCheck(req *admv1.AdmissionRequest) (*common.DecisionResult, []rspapi.ResourceSigningProfile) {
	reqFields := shield.AdmissionRequestToReqFields(req)
	protected, _, matchedProfiels := ruletable.CheckIfProtected(reqFields)
	if !protected {
		dr := &common.DecisionResult{
			Type:       common.DecisionAllow,
			Verified:   false,
			ReasonCode: common.REASON_NOT_PROTECTED,
			Message:    common.ReasonCodeMap[common.REASON_NOT_PROTECTED].Message,
		}
		return dr, nil
	}
	return common.UndeterminedDecision(), matchedProfiels
}

// Check if the request is delete operation
func (server *WebhookServer) deleteCheck(req *admv1.AdmissionRequest) *common.DecisionResult {
	isDelete := (req.Operation == admv1.Delete)
	if isDelete {
		dr := &common.DecisionResult{
			Type:       common.DecisionAllow,
			Verified:   false,
			ReasonCode: common.REASON_SKIP_DELETE,
			Message:    common.ReasonCodeMap[common.REASON_SKIP_DELETE].Message,
		}
		return dr
	}
	return common.UndeterminedDecision()
}

// func createAdmissionResponse(allowed bool, msg string, reqc *common.RequestContext, reqobj *common.RequestObject, ctx *CheckContext, conf *config.ShieldConfig) *admv1.AdmissionResponse {
// 	var patchBytes []byte
// 	if conf.PatchEnabled(reqc) {
// 		// `patchBytes` will be nil if no patch
// 		patchBytes = generatePatchBytes(reqc, reqobj, ctx)
// 	}
// 	responseMessage := fmt.Sprintf("%s (Request: %s)", msg, reqc.Info(nil))
// 	resp := &admv1.AdmissionResponse{
// 		Allowed: allowed,
// 		Result: &metav1.Status{
// 			Message: responseMessage,
// 		},
// 	}
// 	if patchBytes != nil {
// 		patchType := admv1.PatchTypeJSONPatch
// 		resp.Patch = patchBytes
// 		resp.PatchType = &patchType
// 	}
// 	return resp
// }

func createSimpleAdmissionResponse(allowed bool, msg string) *admv1.AdmissionResponse {
	responseMessage := fmt.Sprintf("%s (Request: %s)", msg)
	resp := &admv1.AdmissionResponse{
		Allowed: allowed,
		Result: &metav1.Status{
			Message: responseMessage,
		},
	}
	return resp
}

func (server *WebhookServer) handleAdmissionRequest(admissionReviewReq *admv1.AdmissionReview) *admv1.AdmissionResponse {

	_ = config.InitShieldConfig()

	// init decision result with `undetermined`
	dr := common.UndeterminedDecision()

	// check if the resource is owned by integrity shield and the operation can be allowed
	// TODO: add it

	// check if the request is delete operation; if delete, skip this request
	dr = server.deleteCheck(admissionReviewReq.Request)
	if !dr.IsUndetermined() {
		return createSimpleAdmissionResponse(dr.IsAllowed(), dr.Message)
	}

	var matchedProfiels []rspapi.ResourceSigningProfile
	// check if the group/version/kind is protected in the namespace
	dr, matchedProfiels = server.groupKindNamespaceCheck(admissionReviewReq.Request)
	if !dr.IsUndetermined() {
		return createSimpleAdmissionResponse(dr.IsAllowed(), dr.Message)
	}

	// check mutation & signature & image signature if enabled & some others
	multipleResponses := []*admv1.AdmissionResponse{}
	for _, singleProfile := range matchedProfiels {
		metaLogger := logger.NewLogger(config.ShieldConfig.LoggerConfig())
		requestHandler := shield.NewHandler(config.ShieldConfig, metaLogger, singleProfile)
		// Run Request Handler
		resp := requestHandler.Run(admissionReviewReq.Request)
		multipleResponses = append(multipleResponses, resp)
	}
	admissionResponse, _ := shield.SummarizeMultipleAdmissionResponses(multipleResponses)

	return admissionResponse
}

func (server *WebhookServer) checkLiveness(w http.ResponseWriter, r *http.Request) {
	msg := "liveness ok"
	_, _ = w.Write([]byte(msg))
}

func (server *WebhookServer) checkReadiness(w http.ResponseWriter, r *http.Request) {
	// _, err := http.Get(apiBaseURL + "/probe/readiness")
	// if err != nil {
	// 	http.Error(w, "not ready", http.StatusInternalServerError)
	// 	return
	// }

	msg := "readiness ok"
	_, _ = w.Write([]byte(msg))
}

func (server *WebhookServer) serveRequest(w http.ResponseWriter, r *http.Request) {

	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err != nil {
			http.Error(w, "Could not read admission request", http.StatusBadRequest)
			return
		} else {
			body = data
		}
	}
	if len(body) == 0 {
		http.Error(w, "Admission request has empty body", http.StatusBadRequest)
		return
	}

	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		http.Error(w, " Request has invalid Content-Type, expect `application/json`", http.StatusUnsupportedMediaType)
		return
	}

	var admissionResponse *admv1.AdmissionResponse
	admissionReviewReq := admv1.AdmissionReview{}
	if _, _, err := universalDeserializer.Decode(body, nil, &admissionReviewReq); err != nil {

		admissionResponse = &admv1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}

	} else {

		admissionResponse = server.handleAdmissionRequest(&admissionReviewReq)

	}

	admissionReview := admv1.AdmissionReview{
		TypeMeta: admissionReviewReq.TypeMeta,
	}

	if admissionResponse != nil {
		admissionReview.Response = admissionResponse
		if admissionReviewReq.Request != nil {
			admissionReview.Response.UID = admissionReviewReq.Request.UID
		}
	}

	// Return the AdmissionReview with a response as JSON.
	resp, err := json.Marshal(&admissionReview)

	if err != nil {
		http.Error(w, fmt.Sprintf("marshaling admision review response: %v", err), http.StatusInternalServerError)

	}

	if _, err := w.Write(resp); err != nil {
		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)

	}

}

func createNewServer(certPath, keyPath string) *WebhookServer {
	return &WebhookServer{
		mux:      http.NewServeMux(),
		certPath: certPath,
		keyPath:  keyPath,
	}
}

func (server *WebhookServer) Run() {

	pair, err := tls.LoadX509KeyPair(server.certPath, server.keyPath)

	if err != nil {
		panic(fmt.Sprintf("unable to load certs: %v", err))
	}

	server.mux.HandleFunc("/mutate", server.serveRequest)
	server.mux.HandleFunc("/health/liveness", server.checkLiveness)
	server.mux.HandleFunc("/health/readiness", server.checkReadiness)

	serverObj := &http.Server{
		Addr:      ":8443",
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12},
		Handler:   server.mux,
	}

	if err := serverObj.ListenAndServeTLS("", ""); err != nil {
		panic(fmt.Sprintf("Fail to run webhook server: %v", err))
	}
}
