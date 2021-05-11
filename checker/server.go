package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	sconfloader "github.com/IBM/integrity-enforcer/shield/pkg/config/loader"
	shield "github.com/IBM/integrity-enforcer/shield/pkg/shield"
	logger "github.com/IBM/integrity-enforcer/shield/pkg/util/logger"
	log "github.com/sirupsen/logrus"
	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var config *sconfloader.Config

func init() {
	log.SetFormatter(&log.JSONFormatter{})

	config = sconfloader.NewConfig()
	config.InitShieldConfig()
	logger.Info("Integrity Shield has been started.")

	cfgBytes, _ := json.Marshal(config)
	logger.Trace(string(cfgBytes))
	logger.Info("ShieldConfig is loaded.")
}

func handleRequest(admissionReq *admv1.AdmissionRequest) *shield.DecisionResult {

	_ = config.InitShieldConfig()

	gv := metav1.GroupVersion{Group: admissionReq.Kind.Group, Version: admissionReq.Kind.Version}
	metaLogger := logger.NewLogger(config.ShieldConfig.LoggerConfig())
	reqLog := metaLogger.WithFields(
		log.Fields{
			"namespace":  admissionReq.Namespace,
			"name":       admissionReq.Name,
			"apiVersion": gv.String(),
			"kind":       admissionReq.Kind,
			"operation":  admissionReq.Operation,
			"requestUID": string(admissionReq.UID),
		},
	)
	reqHandler := shield.NewHandler(config.ShieldConfig, metaLogger, reqLog)
	admissionRequest := admissionReq

	//process request
	result := reqHandler.StepRun(admissionRequest)

	return result

}

func handleResource(resource *unstructured.Unstructured) *shield.DecisionResult {

	_ = config.InitShieldConfig()

	objGVK := resource.GetObjectKind().GroupVersionKind()
	gv := metav1.GroupVersion{Group: objGVK.Group, Version: objGVK.Version}
	metaLogger := logger.NewLogger(config.ShieldConfig.LoggerConfig())
	reqLog := metaLogger.WithFields(
		log.Fields{
			"namespace":  resource.GetNamespace(),
			"name":       resource.GetName(),
			"apiVersion": gv.String(),
			"kind":       objGVK.Kind,
		},
	)
	resHandler := shield.NewResourceHandler(config.ShieldConfig, metaLogger, reqLog)

	//process request
	result := resHandler.Run(resource)

	return result

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

	result := handleResource(resource)

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
	http.HandleFunc("/check", defaultHandler)
	http.HandleFunc("/check/request", requestHandler)
	http.HandleFunc("/check/resource", resourceHandler)
	http.HandleFunc("/probe/liveness", checkLiveness)
	http.HandleFunc("/probe/readiness", checkReadiness)
	http.ListenAndServe(":8080", nil)
}
