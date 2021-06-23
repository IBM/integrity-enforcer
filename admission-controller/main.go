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
	"flag"
	"os"

	k8smnfconfig "github.com/IBM/integrity-shield/admission-controller/pkg/config"
	"github.com/IBM/integrity-shield/admission-controller/pkg/shield"
	log "github.com/sirupsen/logrus"
	"github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/k8smanifest"

	"sigs.k8s.io/controller-runtime/pkg/client"

	corev1 "k8s.io/api/core/v1"

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

	//load config (constraint)
	constraints, err := getConstraints()
	if err != nil {
		log.Errorf("failed to load manifest integrity config; %s", err.Error())
		return admission.Allowed("error but allow for development")
	}

	results := []shield.ResultFromRequestHandler{}

	for _, constraint := range constraints {

		//TODO: match check: kind, namespace
		isMatched := matchCheck(req, constraint.Match)
		if !isMatched {
			r := shield.ResultFromRequestHandler{
				Allow:   true,
				Message: "not protected",
			}
			results = append(results, r)
			continue
		}

		//TODO: pick parameters from constaint
		paramObj := k8smnfconfig.GetParametersFromConstraint(constraint)

		// TODO: call request handler
		// TODO: receive result from request handler (allow, message)
		r := shield.RequestHandler(req, paramObj)

		results = append(results, *r)
	}

	// TODO: accumulate results from constraints
	ar := getAccumulatedResult(results)

	// TODO: generate events

	// TODO: update status

	// return admission response
	if ar.Allow {
		return admission.Allowed(ar.Message)
	} else {
		return admission.Denied(ar.Message)
	}
}

func getConstraints() ([]k8smnfconfig.ConstraintObject, error) {
	//TODO: constraintに変える
	configNamespace := getPodNamespace()
	configName := defaultManifestIntegrityConfigMapName
	constraint, err := k8smnfconfig.LoadConfig(configNamespace, configName)
	log.Info("[DEBUG] constraint: ", constraint)
	constraints := []k8smnfconfig.ConstraintObject{}
	if err == nil && constraint != nil {
		constraints = append(constraints, *constraint)
	}
	return constraints, err
}

type AccumulatedResult struct {
	Allow   bool
	Message string
}

func matchCheck(req admission.Request, match k8smanifest.ObjectReferenceList) bool {
	// TODO: fix
	if len(match) == 0 {
		return true
	}
	for _, m := range match {
		if m.Kind == "" {
			return true
		}
		if m.Kind == req.Kind.Kind {
			return true
		}
	}
	return false
}

func getAccumulatedResult(results []shield.ResultFromRequestHandler) *AccumulatedResult {
	accumulatedRes := &AccumulatedResult{}
	for _, result := range results {
		if !result.Allow {
			accumulatedRes.Allow = false
			accumulatedRes.Message = result.Message
			return accumulatedRes
		}
	}
	accumulatedRes.Allow = true
	return accumulatedRes
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
