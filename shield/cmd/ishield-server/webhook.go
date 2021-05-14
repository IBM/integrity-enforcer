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

	sconfloder "github.com/IBM/integrity-enforcer/shield/pkg/config/loader"
	"github.com/IBM/integrity-enforcer/shield/pkg/shield"
	"github.com/IBM/integrity-enforcer/shield/pkg/util/logger"
	log "github.com/sirupsen/logrus"
	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var config *sconfloder.Config

var (
	universalDeserializer = serializer.NewCodecFactory(runtime.NewScheme()).UniversalDeserializer()
)

type WebhookServer struct {
	mux               *http.ServeMux
	certPath, keyPath string
}

func init() {
	log.SetFormatter(&log.JSONFormatter{})

	config = sconfloder.NewConfig()
	config.InitShieldConfig()
	logger.SetSingletonLoggerLevel(config.ShieldConfig.Log.LogLevel)
	logger.Info("Integrity Shield has been started.")

	cfgBytes, _ := json.Marshal(config)
	logger.Trace(string(cfgBytes))
	logger.Info("ShieldConfig is loaded.")
}

func (server *WebhookServer) handleAdmissionRequest(admissionReviewReq *admv1.AdmissionReview) *admv1.AdmissionResponse {

	_ = config.InitShieldConfig()

	gv := metav1.GroupVersion{Group: admissionReviewReq.Request.Kind.Group, Version: admissionReviewReq.Request.Kind.Version}
	metaLogger := logger.NewLogger(config.ShieldConfig.LoggerConfig())
	reqLog := metaLogger.WithFields(
		log.Fields{
			"namespace":  admissionReviewReq.Request.Namespace,
			"name":       admissionReviewReq.Request.Name,
			"apiVersion": gv.String(),
			"kind":       admissionReviewReq.Request.Kind,
			"operation":  admissionReviewReq.Request.Operation,
			"requestUID": string(admissionReviewReq.Request.UID),
		},
	)
	requestHandler := shield.NewHandler(config.ShieldConfig, metaLogger, reqLog)
	admissionRequest := admissionReviewReq.Request

	// Run Request Handler
	admissionResponse := requestHandler.Run(admissionRequest)
	return admissionResponse
}

func (server *WebhookServer) checkLiveness(w http.ResponseWriter, r *http.Request) {
	msg := "liveness ok"
	_, _ = w.Write([]byte(msg))
}

func (server *WebhookServer) checkReadiness(w http.ResponseWriter, r *http.Request) {

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
