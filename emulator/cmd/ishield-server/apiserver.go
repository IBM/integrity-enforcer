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
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	shield "github.com/IBM/integrity-enforcer/shield/pkg/shield"
	logger "github.com/IBM/integrity-enforcer/shield/pkg/util/logger"
	"github.com/ghodss/yaml"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	admv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// singleton
var config *Config

var (
	universalDeserializer = serializer.NewCodecFactory(runtime.NewScheme()).UniversalDeserializer()
)

type APIServer struct {
	mux               *http.ServeMux
	certPath, keyPath string
}

type K8sClient struct {
	client.Client
}

type InputRequest struct {
	UserName  string `json:"userName,omitempty"`
	UserGroup string `json:"userGroup,omitempty"`
	Operation string `json:"operation,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Data      string `json:"data,omitempty"`
}

func init() {
	log.SetFormatter(&log.JSONFormatter{})

	config = NewConfig()
	config.InitShieldConfig()
	logger.Info("Integrity Shield has been started.")

	cfgBytes, _ := json.Marshal(config)
	logger.Trace(string(cfgBytes))
	logger.Info("ShieldConfig is loaded.")
}

func (server *APIServer) handleAdmissionRequest(admissionReviewReq *admv1.AdmissionReview) *admv1.AdmissionResponse {

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
	reqHandler := shield.NewHandler(config.ShieldConfig, metaLogger, reqLog)
	reqHandler.EnableEmulate()
	admissionRequest := admissionReviewReq.Request

	//process request
	admissionResponse := reqHandler.Run(admissionRequest)

	return admissionResponse

}

func (server *APIServer) serveRequest(w http.ResponseWriter, r *http.Request) {

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

	var req *InputRequest
	err := json.Unmarshal(body, &req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to json.Unmarshal() with request body; %s", err.Error()), http.StatusBadRequest)
		return
	}
	dataBytes, _ := base64.URLEncoding.DecodeString(req.Data)
	dataJson, _ := yaml.YAMLToJSON(dataBytes)

	var reqObj *unstructured.Unstructured
	err = yaml.Unmarshal(dataBytes, &reqObj)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to yaml.Unmarshal() with request.Data; %s", err.Error()), http.StatusBadRequest)
		return
	}
	reqName := reqObj.GetName()
	reqNamespace := reqObj.GetNamespace()
	if reqNamespace == "" && req.Namespace != "" {
		reqNamespace = req.Namespace
	}

	u, _ := uuid.NewRandom()

	tmpGvk := reqObj.GetObjectKind().GroupVersionKind()
	gvk := metav1.GroupVersionKind{Group: tmpGvk.Group, Version: tmpGvk.Version, Kind: tmpGvk.Kind}
	tmpGvr, _ := meta.UnsafeGuessKindToResource(tmpGvk)
	gvr := metav1.GroupVersionResource{Group: tmpGvr.Group, Version: tmpGvr.Version, Resource: tmpGvr.Resource}

	var obj, oldObj runtime.RawExtension

	if req.Operation == "CREATE" || req.Operation == "UPDATE" {
		obj = runtime.RawExtension{
			Raw:    dataJson,
			Object: reqObj,
		}
	}

	if req.Operation == "UPDATE" || req.Operation == "DELETE" {
		scheme := runtime.NewScheme()
		cli, _ := ctrlclient.New(ctrl.GetConfigOrDie(), ctrlclient.Options{Scheme: scheme})

		found := &unstructured.Unstructured{}
		found.SetAPIVersion(metav1.GroupVersion{Group: gvk.Group, Version: gvk.Version}.String())
		found.SetKind(gvk.Kind)
		err := cli.Get(context.Background(), types.NamespacedName{Namespace: reqNamespace, Name: reqName}, found)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to get current resource %s, %s; %s", gvk.String(), reqName, err.Error()), http.StatusBadRequest)
			return
		}
		foundBytes, _ := json.Marshal(found)
		oldObj = runtime.RawExtension{
			Raw:    foundBytes,
			Object: found,
		}
	}

	falseVar := false
	admissionReviewReq := admv1.AdmissionReview{
		Request: &admv1.AdmissionRequest{
			UID:       types.UID(u.String()),
			Kind:      gvk,
			Resource:  gvr,
			Name:      reqName,
			Namespace: reqNamespace,
			Object:    obj,
			OldObject: oldObj,
			DryRun:    &falseVar,
		},
	}

	admissionResponse := server.handleAdmissionRequest(&admissionReviewReq)

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

func createNewServer(certPath, keyPath string) *APIServer {
	return &APIServer{
		mux:      http.NewServeMux(),
		certPath: certPath,
		keyPath:  keyPath,
	}
}

func (server *APIServer) Run() {

	pair, err := tls.LoadX509KeyPair(server.certPath, server.keyPath)

	if err != nil {
		panic(fmt.Sprintf("unable to load certs: %v", err))
	}

	server.mux.HandleFunc("/mutate", server.serveRequest)

	serverObj := &http.Server{
		Addr:      ":8443",
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12},
		Handler:   server.mux,
	}

	if err := serverObj.ListenAndServeTLS("", ""); err != nil {
		panic(fmt.Sprintf("Fail to run webhook server: %v", err))
	}
}
