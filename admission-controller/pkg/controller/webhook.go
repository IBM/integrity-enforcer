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

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	miprofile "github.com/IBM/integrity-shield/admission-controller/pkg/apis/manifestintegrityprofile/v1alpha1"
	mipclient "github.com/IBM/integrity-shield/admission-controller/pkg/client/manifestintegrityprofile/clientset/versioned/typed/manifestintegrityprofile/v1alpha1"
	acconfig "github.com/IBM/integrity-shield/admission-controller/pkg/config"
	k8smnfconfig "github.com/IBM/integrity-shield/integrity-shield-server/pkg/config"
	"github.com/IBM/integrity-shield/integrity-shield-server/pkg/shield"
	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	kubeclient "k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const defaultConfigKeyInConfigMap = "config.yaml"
const defaultPodNamespace = "k8s-manifest-sigstore"
const defaultControllerConfigName = "k8s-manifest-controller-config"

type AccumulatedResult struct {
	Allow   bool
	Message string
}

func ProcessRequest(req admission.Request) admission.Response {
	// load ac2 config
	config, err := loadShieldConfig()
	if err != nil {
		log.Errorf("failed to load shield config; %s", err.Error())
		return admission.Allowed("error but allow for development")
	}
	// isScope check
	inScopeNamespace := config.InScopeNamespaceSelector.Match(req.Namespace)
	if !inScopeNamespace {
		return admission.Allowed("this namespace is out of scope")
	}
	// allow check
	allowedRequest := config.Allow.Match(req.Kind)
	if allowedRequest {
		return admission.Allowed("this kind is out of scope")
	}

	// load constraints
	constraints, err := LoadConstraints()
	if err != nil {
		log.Errorf("failed to load constratints; %s", err.Error())
		return admission.Allowed("error but allow for development")
	}

	results := []shield.ResultFromRequestHandler{}

	for _, constraint := range constraints {

		//match check: kind, namespace, label
		isMatched := matchCheck(req, constraint.Match)
		if !isMatched {
			r := shield.ResultFromRequestHandler{
				Allow:   true,
				Message: "not protected",
			}
			results = append(results, r)
			continue
		}

		// pick parameters from constaint
		paramObj := GetParametersFromConstraint(constraint)

		// call request handler & receive result from request handler (allow, message)
		useRemote, _ := strconv.ParseBool(os.Getenv("USE_REMOTE_HANDLER"))
		r := shield.RequestHandlerController(useRemote, req, paramObj)
		// r := handler.RequestHandler(req, paramObj)

		results = append(results, *r)
	}

	// accumulate results from constraints
	ar := getAccumulatedResult(results)

	// TODO: generate events

	// TODO: update status

	// return admission response
	logMsg := fmt.Sprintf("%s %s %s : %s %s", req.Kind.Kind, req.Name, req.Operation, strconv.FormatBool(ar.Allow), ar.Message)
	log.Info("AC2 result: ", logMsg)
	if ar.Allow {
		return admission.Allowed(ar.Message)
	} else {
		return admission.Denied(ar.Message)
	}
}

func GetParametersFromConstraint(constraint miprofile.ManifestIntegrityProfileSpec) *k8smnfconfig.ParameterObject {
	return &constraint.Parameters
}

func loadShieldConfig() (*acconfig.ShieldConfig, error) {
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		namespace = defaultPodNamespace
	}
	configName := os.Getenv("CONTROLLER_CONFIG_NAME")
	if configName == "" {
		configName = defaultControllerConfigName
	}
	configKey := os.Getenv("CONTROLLER_CONFIG_KEY")
	if configKey == "" {
		configKey = defaultConfigKeyInConfigMap
	}
	// load
	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		return nil, nil
	}
	clientset, err := kubeclient.NewForConfig(config)
	if err != nil {
		log.Error(err)
		return nil, nil
	}
	cm, err := clientset.CoreV1().ConfigMaps(namespace).Get(context.Background(), configName, metav1.GetOptions{})
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("failed to get a configmap `%s` in `%s` namespace", configName, namespace))
	}

	cfgBytes, found := cm.Data[configKey]
	if !found {
		return nil, errors.New(fmt.Sprintf("`%s` is not found in configmap", configKey))
	}
	var sc *acconfig.ShieldConfig
	err = yaml.Unmarshal([]byte(cfgBytes), &sc)
	if err != nil {
		return sc, errors.Wrap(err, fmt.Sprintf("failed to unmarshal config.yaml into %T", sc))
	}
	return sc, nil
}

func LoadConstraints() ([]miprofile.ManifestIntegrityProfileSpec, error) {
	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		return nil, nil
	}
	clientset, err := mipclient.NewForConfig(config)
	if err != nil {
		log.Error(err)
		return nil, nil
	}
	miplist, err := clientset.ManifestIntegrityProfiles().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Error("failed to get ManifestIntegrityProfiles:", err.Error())
		return nil, nil
	}
	var constraints []miprofile.ManifestIntegrityProfileSpec
	for _, mip := range miplist.Items {
		constraints = append(constraints, mip.Spec)
	}
	return constraints, nil
}

func matchCheck(req admission.Request, match miprofile.MatchCondition) bool {
	// check if excludedNamespace
	if len(match.ExcludedNamespaces) != 0 {
		for _, ens := range match.ExcludedNamespaces {
			if k8smnfutil.MatchPattern(ens, req.Namespace) {
				return false
			}
		}
	}
	// check if matched kinds/namespace/label
	var nsMatched bool
	var kindsMatched bool
	var labelMatched bool
	var nslabelMatched bool
	nsMatched = checkNamespaceMatch(req, match.Namespaces)
	kindsMatched = checkKindMatch(req, match.Kinds)
	labelMatched = checkLabelMatch(req, match.LabelSelector)
	nslabelMatched = checkNamespaceLabelMatch(req.Namespace, match.NamespaceSelector)

	if nsMatched && kindsMatched && nslabelMatched && labelMatched {
		return true
	}
	return false
}

func checkNamespaceLabelMatch(namespace string, labelSelector *metav1.LabelSelector) bool {
	if labelSelector == nil {
		return true
	}
	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		return false
	}
	clientset, err := kubeclient.NewForConfig(config)
	if err != nil {
		log.Error(err)
		return false
	}
	ns, err := clientset.CoreV1().Namespaces().Get(context.Background(), namespace, metav1.GetOptions{})
	if err != nil {
		log.Errorf("failed to get a namespace `%s`:`%s`", namespace, err.Error())
		return false
	}
	selector, err := metav1.LabelSelectorAsSelector(labelSelector)
	if err != nil {
		log.Errorf("failed to convert the LabelSelector api type into a struct that implements labels.Selector; %s", err.Error())
		return false
	}
	labelsMap := ns.GetLabels()
	labelsSet := labels.Set(labelsMap)
	matched := selector.Matches(labelsSet)
	return matched
}

func checkLabelMatch(req admission.Request, labelSelector *metav1.LabelSelector) bool {
	if labelSelector == nil {
		return true
	}
	var resource unstructured.Unstructured
	objectBytes := req.AdmissionRequest.Object.Raw
	err := json.Unmarshal(objectBytes, &resource)
	if err != nil {
		log.Errorf("failed to Unmarshal a requested object into %T; %s", resource, err.Error())
		return false
	}
	selector, err := metav1.LabelSelectorAsSelector(labelSelector)
	if err != nil {
		log.Errorf("failed to convert the LabelSelector api type into a struct that implements labels.Selector; %s", err.Error())
		return false
	}
	labelsMap := resource.GetLabels()
	labelsSet := labels.Set(labelsMap)
	matched := selector.Matches(labelsSet)
	return matched
}

func checkNamespaceMatch(req admission.Request, match []string) bool {
	matched := false
	if len(match) == 0 {
		matched = true
	} else {
		// check if cluster scope
		if req.Namespace == "" {
			matched = true
		}
		for _, ns := range match {
			if k8smnfutil.MatchPattern(ns, req.Namespace) {
				matched = true
			}
		}
	}
	return matched
}

func checkKindMatch(req admission.Request, match []miprofile.Kinds) bool {
	matched := false
	if len(match) == 0 {
		matched = true
	} else {
		for _, kinds := range match {
			kind := false
			group := false
			if len(kinds.Kinds) == 0 {
				kind = true
			} else {
				for _, k := range kinds.Kinds {
					if k8smnfutil.MatchPattern(k, req.Kind.Kind) {
						kind = true
					}
				}
			}
			if len(kinds.ApiGroups) == 0 {
				group = true
			} else {
				for _, g := range kinds.ApiGroups {
					if k8smnfutil.MatchPattern(g, req.Kind.Group) {
						group = true
					}
				}
			}
			if kind && group {
				matched = true
			}
		}
	}
	return matched
}

func getAccumulatedResult(results []shield.ResultFromRequestHandler) *AccumulatedResult {
	denyMessages := []string{}
	allowMessages := []string{}
	accumulatedRes := &AccumulatedResult{}
	for _, result := range results {
		if !result.Allow {
			accumulatedRes.Message = result.Message
			denyMessages = append(denyMessages, result.Message)
		} else {
			allowMessages = append(allowMessages, result.Message)
		}
	}
	if len(denyMessages) != 0 {
		accumulatedRes.Allow = false
		accumulatedRes.Message = strings.Join(denyMessages, ";")
		return accumulatedRes
	}
	accumulatedRes.Allow = true
	accumulatedRes.Message = strings.Join(allowMessages, ";")
	return accumulatedRes
}
