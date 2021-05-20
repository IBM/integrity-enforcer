package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"path"

	sconfloader "github.com/IBM/integrity-enforcer/shield/pkg/config/loader"
	shield "github.com/IBM/integrity-enforcer/shield/pkg/shield"
	logger "github.com/IBM/integrity-enforcer/shield/pkg/util/logger"
	log "github.com/sirupsen/logrus"
	admv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	tlsDir      = `/run/secrets/tls`
	tlsCertFile = `tls.crt`
	tlsKeyFile  = `tls.key`
)

var config *sconfloader.Config

func init() {
	log.SetFormatter(&log.JSONFormatter{})

	config = sconfloader.NewConfig()
	_ = config.InitShieldConfig()
	logger.Info("Integrity Shield has been started.")

	cfgBytes, _ := json.Marshal(config)
	logger.Trace(string(cfgBytes))
	logger.Info("ShieldConfig is loaded.")
}

func handleRequest(admissionReq *admv1.AdmissionRequest) *admv1.AdmissionResponse {

	_ = config.InitShieldConfig()

	metaLogger := logger.NewLogger(config.ShieldConfig.LoggerConfig())
	reqHandler := shield.NewHandler(config.ShieldConfig, metaLogger)
	admissionRequest := admissionReq

	//process request
	result := reqHandler.Run(admissionRequest)

	return result

}

func handleResource(resource *unstructured.Unstructured) (*shield.DecisionResult, *shield.CheckContext) {

	_ = config.InitShieldConfig()

	metaLogger := logger.NewLogger(config.ShieldConfig.LoggerConfig())
	resHandler := shield.NewResourceCheckHandler(config.ShieldConfig, metaLogger)

	//process request
	dr := resHandler.Run(resource)
	ctx := resHandler.GetCheckContext()

	return dr, ctx

}

func defaultHandler(w http.ResponseWriter, r *http.Request) {
	errorHandler(w, r, http.StatusNotFound)
}

func errorHandler(w http.ResponseWriter, r *http.Request, status int) {
	w.WriteHeader(status)
	if status == http.StatusNotFound {
		fmt.Fprint(w, "Custom 404")
	}
}

func requestHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if r.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	bufbody := new(bytes.Buffer)
	_, _ = bufbody.ReadFrom(r.Body)
	body := bufbody.Bytes()

	fmt.Println("Body:", string(body))

	var request *admv1.AdmissionRequest
	err := json.Unmarshal(body, &request)
	if err != nil {
		http.Error(w, fmt.Sprintf("unmarshaling input data as admission review: %v", err), http.StatusInternalServerError)
		return
	}

	result := handleRequest(request)

	resp, err := json.Marshal(result)
	if err != nil {
		http.Error(w, fmt.Sprintf("marshaling request handler result: %v", err), http.StatusInternalServerError)
		return

	}
	fmt.Println("Response:", string(resp))

	if _, err := w.Write(resp); err != nil {
		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
		return
	}
}

func resourceHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if r.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	bufbody := new(bytes.Buffer)
	_, _ = bufbody.ReadFrom(r.Body)
	body := bufbody.Bytes()

	fmt.Println("Body:", string(body))

	var resource *unstructured.Unstructured
	err := json.Unmarshal(body, &resource)
	if err != nil {
		http.Error(w, fmt.Sprintf("unmarshaling input data as unstructured.Unstructured: %v", err), http.StatusInternalServerError)
		return
	}

	dr, ctx := handleResource(resource)

	result := map[string]interface{}{
		"result":  dr,
		"context": ctx,
	}

	resultBytes, err := json.Marshal(result)
	if err != nil {
		http.Error(w, fmt.Sprintf("marshaling resource handler result: %v", err), http.StatusInternalServerError)
		return

	}
	fmt.Println("Result:", string(resultBytes))

	if _, err := w.Write(resultBytes); err != nil {
		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
		return
	}
}

func checkLiveness(w http.ResponseWriter, r *http.Request) {
	msg := "liveness ok"
	_, _ = w.Write([]byte(msg))
}

func checkReadiness(w http.ResponseWriter, r *http.Request) {
	msg := "readiness ok"
	_, _ = w.Write([]byte(msg))
}

func main() {
	tlsCertPath := path.Join(tlsDir, tlsCertFile)
	tlsKeyPath := path.Join(tlsDir, tlsKeyFile)

	pair, err := tls.LoadX509KeyPair(tlsCertPath, tlsKeyPath)

	if err != nil {
		panic(fmt.Sprintf("unable to load certs: %v", err))
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/api", defaultHandler)
	mux.HandleFunc("/api/request", requestHandler)
	mux.HandleFunc("/api/resource", resourceHandler)
	mux.HandleFunc("/api/profile", defaultHandler)
	mux.HandleFunc("/health/liveness", checkLiveness)
	mux.HandleFunc("/health/readiness", checkReadiness)

	serverObj := &http.Server{
		Addr:      ":8080",
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12},
		Handler:   mux,
	}

	if err := serverObj.ListenAndServeTLS("", ""); err != nil {
		panic(fmt.Sprintf("Fail to run integrity shield api server: %v", err))
	}
}
