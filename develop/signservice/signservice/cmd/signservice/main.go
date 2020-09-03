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
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/IBM/integrity-enforcer/develop/signservice/signservice/pkg/cert"
	"github.com/IBM/integrity-enforcer/develop/signservice/signservice/pkg/sign"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

func init() {
	log.SetFormatter(&log.JSONFormatter{})
	log.SetLevel(log.DebugLevel)
}

func getParamInRequest(r *http.Request, key, defaultValue string) string {
	params, ok := r.URL.Query()[key]
	param := params[0]
	if !ok {
		param = defaultValue
	}
	return param
}

func readFileInRequest(r *http.Request, key string) (string, error) {
	yamlFile, _, err := r.FormFile(key)
	defer yamlFile.Close()
	if err != nil {
		return "", err
	}
	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, yamlFile); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "get request: ", r)
}

func signToAnnotation(w http.ResponseWriter, r *http.Request, verifyType string) {
	signer := getParamInRequest(r, "signer", "")
	scope := getParamInRequest(r, "scope", "")
	modeStr := getParamInRequest(r, "mode", "apply")
	mode := sign.DefaultSign
	if modeStr == "apply" {
		mode = sign.ApplySign
	} else if modeStr == "patch" {
		mode = sign.PatchSign
	}

	yamlStr, err := readFileInRequest(r, "yaml")
	if err != nil {
		msg := err.Error()
		log.Error(msg)
		fmt.Fprint(w, msg)
		return
	}

	sig, err := sign.SignYaml(yamlStr, scope, signer, mode, verifyType)
	if err != nil {
		log.Error(err)
		return
	}
	fmt.Fprint(w, sig)
}

func SignToAnnotation(w http.ResponseWriter, r *http.Request) {
	signToAnnotation(w, r, "x509")
}

func PGPSignToAnnotation(w http.ResponseWriter, r *http.Request) {
	signToAnnotation(w, r, "pgp")
}

func signToResourceSignature(w http.ResponseWriter, r *http.Request, mode sign.SignMode, verifyType string) {
	signer := getParamInRequest(r, "signer", "")
	namespace := getParamInRequest(r, "namespace", "")
	scope := getParamInRequest(r, "scope", "")

	yamlStr, err := readFileInRequest(r, "yaml")
	if err != nil {
		msg := err.Error()
		log.Error(msg)
		fmt.Fprint(w, msg)
		return
	}

	rsig, err := sign.CreateResourceSignature(yamlStr, signer, namespace, scope, mode, verifyType)
	if err != nil {
		msg := err.Error()
		log.Error(msg)
		fmt.Fprint(w, msg)
		return
	}
	sig, err := sign.SignYaml(rsig, "spec", signer, sign.DefaultSign, verifyType)
	if err != nil {
		msg := err.Error()
		log.Error(msg)
		fmt.Fprint(w, msg)
		return
	}
	fmt.Fprint(w, sig)
}

func SignToResourceSignature(w http.ResponseWriter, r *http.Request) {
	signToResourceSignature(w, r, sign.DefaultSign, "x509")
}

func ApplySignToResourceSignature(w http.ResponseWriter, r *http.Request) {
	signToResourceSignature(w, r, sign.ApplySign, "x509")
}

func PatchSignToResourceSignature(w http.ResponseWriter, r *http.Request) {
	signToResourceSignature(w, r, sign.PatchSign, "x509")
}

func PGPSignToResourceSignature(w http.ResponseWriter, r *http.Request) {
	signToResourceSignature(w, r, sign.DefaultSign, "pgp")
}

func PGPApplySignToResourceSignature(w http.ResponseWriter, r *http.Request) {
	signToResourceSignature(w, r, sign.ApplySign, "pgp")
}

func PGPPatchSignToResourceSignature(w http.ResponseWriter, r *http.Request) {
	signToResourceSignature(w, r, sign.PatchSign, "pgp")
}

func signBytes(w http.ResponseWriter, r *http.Request, verifyType string) {
	msg, err := readFileInRequest(r, "yaml")
	if err != nil {
		log.Error(err.Error())
		fmt.Fprint(w, err.Error())
		return
	}
	signer := getParamInRequest(r, "signer", "")
	result, err := sign.SignBytes([]byte(msg), signer, verifyType)
	if err != nil {
		log.Error(err.Error())
		fmt.Fprint(w, err.Error())
		return
	}
	fmt.Fprint(w, string(result))
}

func SignBytes(w http.ResponseWriter, r *http.Request) {
	signBytes(w, r, "x509")
}

func PGPSignBytes(w http.ResponseWriter, r *http.Request) {
	signBytes(w, r, "pgp")
}

func ListUsers(w http.ResponseWriter, r *http.Request) {
	mode := "all"

	if _, ok := r.URL.Query()["valid"]; ok {
		mode = "valid"
	}
	if _, ok := r.URL.Query()["invalid"]; ok {
		mode = "invalid"
	}

	userStr, err := sign.ListUsers(mode)
	if err != nil {
		msg := err.Error()
		log.Error(msg)
		fmt.Fprint(w, msg)
		return
	}
	fmt.Fprint(w, userStr)
}

func ListCerts(w http.ResponseWriter, r *http.Request) {
	mode := "all"

	certStr, err := sign.ListCerts(mode)
	if err != nil {
		msg := err.Error()
		log.Error(msg)
		fmt.Fprint(w, msg)
		return
	}
	fmt.Fprint(w, certStr)
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", ServeHTTP)
	r.HandleFunc("/sign", SignToResourceSignature)
	r.HandleFunc("/sign/bytes", SignBytes)
	r.HandleFunc("/sign/apply", ApplySignToResourceSignature)
	r.HandleFunc("/sign/patch", PatchSignToResourceSignature)
	r.HandleFunc("/sign/annotation", SignToAnnotation)
	r.HandleFunc("/pgpsign", PGPSignToResourceSignature)
	r.HandleFunc("/pgpsign/bytes", PGPSignBytes)
	r.HandleFunc("/pgpsign/apply", PGPApplySignToResourceSignature)
	r.HandleFunc("/pgpsign/patch", PGPPatchSignToResourceSignature)
	r.HandleFunc("/pgpsign/annotation", PGPSignToAnnotation)
	r.HandleFunc("/list/users", ListUsers)
	r.HandleFunc("/list/certs", ListCerts)
	r.Schemes("https")

	tlsConfig, err := cert.LoadTLSConfig()
	if err != nil {
		log.Fatal("Failed to load server cert files. Exiting...")
	}

	http.Handle("/", r)

	srv := &http.Server{
		Handler:      r,
		Addr:         "localhost:8180",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
		TLSConfig:    tlsConfig,
	}

	log.Info("SignService server is starting...")
	log.Fatal(srv.ListenAndServeTLS(cert.CertPath, cert.KeyPath))
}
