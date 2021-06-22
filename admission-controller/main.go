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
	"encoding/json"
	"flag"
	"fmt"
	"os"

	k8smnfconfig "github.com/IBM/integrity-shield/admission-controller/pkg/config"
	log "github.com/sirupsen/logrus"
	"github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/k8smanifest"

	"sigs.k8s.io/controller-runtime/pkg/client"

	corev1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

const tlsDir = `/run/secrets/tls`
const podNamespaceEnvKey = "POD_NAMESPACE"
const defaultPodNamespace = "k8s-manifest-sigstore"
const defaultManifestIntegrityConfigMapName = "k8s-manifest-integrity-config"

// +kubebuilder:webhook:path=/validate-resource,mutating=false,failurePolicy=ignore,sideEffects=NoneOnDryRun,groups=*,resources=*,verbs=create;update,versions=*,name=k8smanifest.sigstore.dev,admissionReviewVersions={v1,v1beta1}

type k8sManifestHandler struct {
	Client client.Client
}

func getPodNamespace() string {
	ns := os.Getenv(podNamespaceEnvKey)
	if ns == "" {
		ns = defaultPodNamespace
	}
	return ns
}

func (h *k8sManifestHandler) Handle(ctx context.Context, req admission.Request) admission.Response {

	log.Info("[DEBUG] request: ", req.Kind, ", ", req.Name)

	//unmarshal admission request object
	var rawObj unstructured.Unstructured
	objectBytes := req.AdmissionRequest.Object.Raw
	err := json.Unmarshal(objectBytes, &rawObj)
	if err != nil {
		log.Errorf("failed to Unmarshal a requested object into %T; %s", rawObj, err.Error())
		return admission.Allowed("error but allow for development")
	}

	//config (constraint) を取る
	constraints, err := getConstraints()
	if err != nil {
		log.Errorf("failed to load manifest integrity config; %s", err.Error())
		return admission.Allowed("error but allow for development")
	}

	results := []ResultFromRequestHandler{}

	for _, constraint := range constraints {

		//TODO: match check

		//TODO: pick parameters from constaint
		paramObj := getParametersFromConstraint(constraint)

		//TODO: call request handler
		// TODO: receive result from request handler (allow, message)
		r := requestHandler(req, paramObj)

		results = append(results, *r)
	}

	// TODO: accumulate results from constraints
	ar := getAccumulatedResult(results)

	// TODO: generate events

	// TODO: update status

	// return admission response
	if ar.allow {
		return admission.Allowed(ar.message)
	} else {
		return admission.Denied(ar.message)
	}
}

//RequestHandler

func requestHandler(req admission.Request, paramObj *ParameterObject) *ResultFromRequestHandler {

	//unmarshal admission request object
	var rawObj unstructured.Unstructured
	objectBytes := req.AdmissionRequest.Object.Raw
	err := json.Unmarshal(objectBytes, &rawObj)
	if err != nil {
		log.Errorf("failed to Unmarshal a requested object into %T; %s", rawObj, err.Error())
		return &ResultFromRequestHandler{
			allow:   true,
			message: "error but allow for development",
		}
	}

	//filter by user
	skipUserMatched := paramObj.SkipUsers.Match(rawObj, req.AdmissionRequest.UserInfo.Username)

	//check scope
	inScopeObjMatched := paramObj.InScopeObjects.Match(rawObj)

	allow := true
	message := ""
	if skipUserMatched {
		allow = true
		message = "ignore user config matched"
	} else if !inScopeObjMatched {
		allow = true
		message = "this resource is not in scope of verification"
	} else {
		imageRef := paramObj.ImageRef
		keyPath := ""
		if paramObj.KeySecertName != "" {
			keyPath, _ = k8smnfconfig.LoadKeySecret(paramObj.KeySecertNamespace, paramObj.KeySecertName)
		}
		vo := &(paramObj.VerifyOption)
		result, err := k8smanifest.VerifyResource(rawObj, imageRef, keyPath, vo)
		if err != nil {
			log.Errorf("failed to check a requested resource; %s", err.Error())
			return &ResultFromRequestHandler{
				allow:   true,
				message: "error but allow for development",
			}
		}
		if result.InScope {
			if result.Verified {
				allow = true
				message = fmt.Sprintf("singed by a valid signer: %s", result.Signer)
			} else {
				allow = false
				message = "no signature found"
				if result.Diff != nil && result.Diff.Size() > 0 {
					message = fmt.Sprintf("diff found: %s", result.Diff.String())
				}
				if result.Signer != "" {
					message = fmt.Sprintf("signer config not matched, this is signed by %s", result.Signer)
				}
			}
		} else {
			allow = true
			message = "not protected"
		}
	}

	r := &ResultFromRequestHandler{
		allow:   allow,
		message: message,
	}

	log.Info("[DEBUG] result:", message)

	return r
}

type ParameterObject struct {
	k8smanifest.VerifyOption `json:""`
	InScopeObjects           k8smanifest.ObjectReferenceList    `json:"inScopeObjects,omitempty"`
	SkipUsers                k8smnfconfig.ObjectUserBindingList `json:"skipUsers,omitempty"`
	KeySecertName            string                             `json:"keySecretName,omitempty"`
	KeySecertNamespace       string                             `json:"keySecretNamespace,omitempty"`
	ImageRef                 string                             `json:"imageRef,omitempty"`
}

type ConstraintObject struct {
	constraint string
}

type ResultFromRequestHandler struct {
	allow   bool
	message string
}

func getConstraints() ([]k8smnfconfig.ManifestIntegrityConfig, error) {
	//TODO: constraintに変える
	configNamespace := getPodNamespace()
	configName := defaultManifestIntegrityConfigMapName
	constraint, err := k8smnfconfig.LoadConfig(configNamespace, configName)
	constratins := []k8smnfconfig.ManifestIntegrityConfig{}
	if err == nil && constraint != nil {
		constratins = append(constratins, *constraint)
	}
	return constratins, err
}

func getParametersFromConstraint(constraint k8smnfconfig.ManifestIntegrityConfig) *ParameterObject {
	return &ParameterObject{}
}

type AccumulatedResult struct {
	allow   bool
	message string
}

func getAccumulatedResult(results []ResultFromRequestHandler) *AccumulatedResult {
	return &AccumulatedResult{}
}

func init() {
	_ = clientgoscheme.AddToScheme(scheme)

	_ = corev1.AddToScheme(scheme)
	// +kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	flag.StringVar(&metricsAddr, "metrics-addr", ":8080", "The address the metric endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsAddr,
		Port:               9443,
		LeaderElection:     enableLeaderElection,
		LeaderElectionID:   "22a603b9.sigstore.dev",
		CertDir:            tlsDir,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	hookServer := mgr.GetWebhookServer()
	hookServer.Register("/validate-resource", &webhook.Admission{Handler: &k8sManifestHandler{Client: mgr.GetClient()}})

	// +kubebuilder:scaffold:builder

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
