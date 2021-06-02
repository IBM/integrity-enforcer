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
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

// const (
// 	apiBaseURLEnvKey  = "CHECKER_API_BASE_URL"
// 	defaultAPIBaseURL = "http://integrity-shield-checker:8080"
// )

// var apiBaseURL string

var sConfig *sconfloder.Config

var (
	universalDeserializer = serializer.NewCodecFactory(runtime.NewScheme()).UniversalDeserializer()
)

type WebhookServer struct {
	mux      *http.ServeMux
	certPath string
	keyPath  string
	data     *runtimeData
}

type runtimeData struct {
	rspLoader *RSPLoader
	nsLoader  *NamespaceLoader
	ruletable *RuleTable
}

// create runtimeData instance, load RSPs and NSs and set ruletable
func newRuntimeData() *runtimeData {
	d := &runtimeData{}
	d.rspLoader = NewRSPLoader()
	d.nsLoader = NewNamespaceLoader()
	rspList, _ := d.rspLoader.GetData(true)
	nsList, _ := d.nsLoader.GetData(true)
	d.ruletable = NewRuleTable(rspList, nsList, sConfig.ShieldConfig.CommonProfile, sConfig.ShieldConfig.Namespace)
	if d.ruletable == nil {
		logger.Error("Failed to initialize rule table.")
	}
	return d
}

func (d *runtimeData) clearCache() {
	d.rspLoader.ClearCache()
	d.nsLoader.ClearCache()
}

func init() {
	sConfig = sconfloder.NewConfig()
	_ = sConfig.InitShieldConfig()

	log.SetFormatter(&log.JSONFormatter{})

	logger.SetSingletonLoggerLevel(sConfig.ShieldConfig.Log.LogLevel)
	logger.Info("Integrity Shield has been started.")

	// apiBaseURL = os.Getenv(apiBaseURLEnvKey)
	// if apiBaseURL == "" {
	// 	apiBaseURL = defaultAPIBaseURL
	// }
}

func (server *WebhookServer) iShieldResourceCheck(req *admv1.AdmissionRequest) *common.DecisionResult {
	gv := schema.GroupVersion{Group: req.Kind.Group, Version: req.Kind.Version}
	resRef := &common.ResourceRef{
		ApiVersion: gv.String(),
		Kind:       req.Kind.Kind,
		Namespace:  req.Namespace,
		Name:       req.Name,
	}
	iShieldOperatorResource := sConfig.ShieldConfig.IShieldResourceCondition.IsOperatorResource(resRef)
	iShieldServerResource := sConfig.ShieldConfig.IShieldResourceCondition.IsServerResource(resRef)

	isIShieldResource := false
	if !iShieldOperatorResource && !iShieldServerResource {
		return common.UndeterminedDecision()
	} else {
		isIShieldResource = true
	}

	adminReq := checkIfIShieldAdminRequest(req.UserInfo.Username, req.UserInfo.Groups, sConfig.ShieldConfig)
	serverReq := checkIfIShieldServerRequest(req.UserInfo.Username, sConfig.ShieldConfig)
	operatorReq := checkIfIShieldOperatorRequest(req.UserInfo.Username, sConfig.ShieldConfig)
	gcReq := checkIfGarbageCollectorRequest(req.UserInfo.Username)
	spSAReq := checkIfSpecialServiceAccountRequest(req.UserInfo.Username) && (req.Kind.Kind != "ClusterServiceVersion")

	if (iShieldOperatorResource && (adminReq || operatorReq || gcReq || spSAReq)) || (iShieldServerResource && (operatorReq || serverReq || gcReq || spSAReq)) {
		return &common.DecisionResult{
			Type:            common.DecisionAllow,
			Verified:        true,
			IShieldResource: isIShieldResource,
			ReasonCode:      common.REASON_ISHIELD_ADMIN,
			Message:         common.ReasonCodeMap[common.REASON_ISHIELD_ADMIN].Message,
		}
	} else {
		return &common.DecisionResult{
			Type:            common.DecisionDeny,
			Verified:        false,
			IShieldResource: isIShieldResource,
			ReasonCode:      common.REASON_BLOCK_ISHIELD_RESOURCE_OPERATION,
			Message:         common.ReasonCodeMap[common.REASON_BLOCK_ISHIELD_RESOURCE_OPERATION].Message,
		}
	}
}

// Check if any profile matches the request (this can be replaced with gatekeeper constraints matching + rego)
func (server *WebhookServer) protectedCheck(req *admv1.AdmissionRequest) (*common.DecisionResult, []rspapi.ResourceSigningProfile) {
	reqFields := shield.AdmissionRequestToReqFields(req)
	protected, _, matchedProfiles := server.data.ruletable.CheckIfProtected(reqFields)
	if !protected {
		dr := &common.DecisionResult{
			Type:       common.DecisionAllow,
			Verified:   false,
			ReasonCode: common.REASON_NOT_PROTECTED,
			Message:    common.ReasonCodeMap[common.REASON_NOT_PROTECTED].Message,
		}
		return dr, nil
	}
	return common.UndeterminedDecision(), matchedProfiles
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

func (server *WebhookServer) formatCheckForIShieldCRDs(req *admv1.AdmissionRequest) *common.DecisionResult {
	if ok, msg := shield.ValidateResourceForAdmissionRequest(req, sConfig.ShieldConfig.Namespace); !ok {
		return &common.DecisionResult{
			Type:       common.DecisionDeny,
			ReasonCode: common.REASON_VALIDATION_FAIL,
			Message:    msg,
		}
	}
	return common.UndeterminedDecision()
}

func (server *WebhookServer) handleAdmissionRequest(admissionReviewReq *admv1.AdmissionReview) *admv1.AdmissionResponse {

	server.initializeHandling()

	dr, ctx, profile := server.checkByAdmissionRequest(admissionReviewReq.Request)

	_ = server.report(admissionReviewReq.Request, dr, profile)

	server.finalizeHandling(admissionReviewReq.Request, dr)

	return createAdmissionResponse(dr.IsAllowed(), dr.Message, admissionReviewReq.Request, ctx, sConfig.ShieldConfig)
}

func (server *WebhookServer) checkByAdmissionRequest(req *admv1.AdmissionRequest) (*common.DecisionResult, *common.CheckContext, *rspapi.ResourceSigningProfile) {
	// init decision result with `undetermined`
	dr := common.UndeterminedDecision()

	// this step is an alternative step of gatekeeper+constraints+rego
	var matchedProfiles []rspapi.ResourceSigningProfile
	dr, matchedProfiles = server.admissionSideCheck(req)
	if !dr.IsUndetermined() {
		return dr, nil, nil
	}

	// check mutation & signature & image signature if enabled & some others
	multipleResults := []*common.DecisionResult{}
	multipleCtx := []*common.CheckContext{}
	for _, profile := range matchedProfiles {
		metaLogger := logger.NewLogger(sConfig.ShieldConfig.LoggerConfig())
		requestHandler := shield.NewHandler(sConfig.ShieldConfig, metaLogger, profile.Spec.Parameters)
		// Run Request Handler
		tmpDr := requestHandler.Decide(req)
		tmpCtx := requestHandler.GetCheckContext()
		multipleResults = append(multipleResults, tmpDr)
		multipleCtx = append(multipleCtx, tmpCtx)
	}
	var index int
	dr, index = shield.SummarizeMultipleDecisionResults(multipleResults)
	var ctx *common.CheckContext
	var profile *rspapi.ResourceSigningProfile
	if index > 0 {
		ctx = multipleCtx[index]
		profile = &(matchedProfiles[index])
	}
	return dr, ctx, profile
}

// check if the request should be checked by the subsequent steps
// (i.e. this is an alternative step of gatekeeper+constraints+rego)
func (server *WebhookServer) admissionSideCheck(req *admv1.AdmissionRequest) (*common.DecisionResult, []rspapi.ResourceSigningProfile) {
	// init decision result with `undetermined`
	dr := common.UndeterminedDecision()

	// check if the resource is owned by integrity shield and the operation can be allowed
	// In case of gatekeeper-enabled IShield, this step should be implemented in rego
	dr = server.iShieldResourceCheck(req)
	if !dr.IsUndetermined() {
		return dr, nil
	}

	// check if the request is delete operation; if delete, skip this request
	// In case of gatekeeper-enabled IShield, this step is done by gatekeeper automatically
	dr = server.deleteCheck(req)
	if !dr.IsUndetermined() {
		return dr, nil
	}

	// check if the requested resource kind is an IShield CRD, and check if the format is valid
	// In case of gatekeeper-enabled IShield, this step is not invoked because the CRD kind (e.g. ShieldConfig) is not protected by contraints in general
	// TODO: need to find a way to set a correct CRD schema in ishield operator
	dr = server.formatCheckForIShieldCRDs(req)
	if !dr.IsUndetermined() {
		return dr, nil
	}

	var matchedProfiles []rspapi.ResourceSigningProfile
	// check if the group/version/kind is protected in the namespace
	// In case of gatekeeper-enabled IShield, this step is separated into 2 logics.
	// One is done by gatekeeper automatically, and another should be implemented in rego
	dr, matchedProfiles = server.protectedCheck(req)
	if !dr.IsUndetermined() {
		return dr, nil
	}

	return common.UndeterminedDecision(), matchedProfiles
}

// create Event & update RSP status if sideEffectConfig enabled
func (server *WebhookServer) report(req *admv1.AdmissionRequest, dr *common.DecisionResult, denyRSP *rspapi.ResourceSigningProfile) error {

	// report only for denying request or for IShield resource request by IShield Admin
	shouldReport := false
	if !dr.IsAllowed() && sConfig.ShieldConfig.SideEffect.CreateDenyEventEnabled() {
		shouldReport = true
	}
	iShieldAdmin := checkIfIShieldAdminRequest(req.UserInfo.Username, req.UserInfo.Groups, sConfig.ShieldConfig)
	if dr.IShieldResource && !iShieldAdmin && sConfig.ShieldConfig.SideEffect.CreateIShieldResourceEventEnabled() {
		shouldReport = true
	}

	if !shouldReport {
		return nil
	}

	var err error
	// create/update Event
	if sConfig.ShieldConfig.SideEffect.CreateEventEnabled() {
		err = createOrUpdateEvent(req, dr, sConfig.ShieldConfig, denyRSP)
		if err != nil {
			logger.Error("Failed to create event; ", err)
			return err
		}
	}

	// update RSP status for deny event
	if sConfig.ShieldConfig.SideEffect.UpdateRSPStatusEnabled() && dr.IsDenied() && denyRSP != nil {
		err = updateRSPStatus(denyRSP, req, dr.Message)
		if err != nil {
			logger.Error("Failed to update status; ", err)
		}
	}

	return nil
}

func (server *WebhookServer) initializeHandling() {
	_ = sConfig.InitShieldConfig()

	// set rule table using cache if provided, otherwise, load RSPs and NSs via K8s API
	server.data = newRuntimeData()
}

// clear RSP / NS cache if needed
func (server *WebhookServer) finalizeHandling(req *admv1.AdmissionRequest, dr *common.DecisionResult) {
	reqIsAllowed := dr.IsAllowed()
	if !reqIsAllowed {
		return
	}
	reqForRSP := (req.Kind.Kind == common.ProfileCustomResourceKind)
	reqForNS := (req.Kind.Kind == "Namespace")
	if !(reqForRSP || reqForNS) {
		return
	}
	reqByIShieldServer := checkIfIShieldServerRequest(req.UserInfo.Username, sConfig.ShieldConfig)
	reqByIShieldOperator := checkIfIShieldOperatorRequest(req.UserInfo.Username, sConfig.ShieldConfig)
	if reqByIShieldServer || reqByIShieldOperator {
		return
	}
	shouldClearCache := false
	if reqForRSP {
		shouldClearCache = true
	} else if reqForNS {
		mutationCheckResult, _ := shield.MutationCheckForAdmissionRequest(req)
		if mutationCheckResult.IsMutated {
			shouldClearCache = true
		}
	}

	if shouldClearCache {
		server.data.clearCache()
	}
	return
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
