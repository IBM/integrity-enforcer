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

func SignToAnnotation(w http.ResponseWriter, r *http.Request) {
	scopeConcatKey, ok := r.URL.Query()["scope"]
	if !ok {
		msg := "param `scope` is required.  e.g.) /sign/annotation?scope=spec"
		log.Error(msg)
		fmt.Fprint(w, msg)
		return
	}
	scopeKeys := scopeConcatKey[0]

	signer := getParamInRequest(r, "signer", "")

	yamlStr, err := readFileInRequest(r, "yaml")
	if err != nil {
		msg := err.Error()
		log.Error(msg)
		fmt.Fprint(w, msg)
		return
	}

	sig, err := sign.SignYaml(yamlStr, scopeKeys, signer)
	if err != nil {
		log.Error(err)
		return
	}
	fmt.Fprint(w, sig)
}

func signToResourceSignature(w http.ResponseWriter, r *http.Request, mode sign.SignMode) {
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

	rsig, err := sign.CreateResourceSignature(yamlStr, signer, namespace, scope, mode)
	if err != nil {
		msg := err.Error()
		log.Error(msg)
		fmt.Fprint(w, msg)
		return
	}
	sig, err := sign.SignYaml(rsig, "spec", signer)
	if err != nil {
		msg := err.Error()
		log.Error(msg)
		fmt.Fprint(w, msg)
		return
	}
	fmt.Fprint(w, sig)
}

func SignToResourceSignature(w http.ResponseWriter, r *http.Request) {
	signToResourceSignature(w, r, sign.DefaultSign)
}

func ApplySignToResourceSignature(w http.ResponseWriter, r *http.Request) {
	signToResourceSignature(w, r, sign.ApplySign)
}

func PatchSignToResourceSignature(w http.ResponseWriter, r *http.Request) {
	signToResourceSignature(w, r, sign.PatchSign)
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

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", ServeHTTP)
	r.HandleFunc("/sign", SignToResourceSignature)
	r.HandleFunc("/sign/apply", ApplySignToResourceSignature)
	r.HandleFunc("/sign/patch", PatchSignToResourceSignature)
	r.HandleFunc("/sign/annotation", SignToAnnotation)
	r.HandleFunc("/list/users", ListUsers)
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
