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

package observer

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	k8smnfconfig "github.com/IBM/integrity-shield/integrity-shield-server/pkg/config"
	ishield "github.com/IBM/integrity-shield/integrity-shield-server/pkg/shield"
	vrres "github.com/IBM/integrity-shield/observer/pkg/apis/verifyresourcestatus/v1alpha1"
	vrresclient "github.com/IBM/integrity-shield/observer/pkg/client/verifyresourcestatus/clientset/versioned/typed/verifyresourcestatus/v1alpha1"
	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const timeFormat = "2006-01-02 15:04:05"

const defaultConfigKeyInConfigMap = "config.yaml"
const defaultPodNamespace = "k8s-manifest-sigstore"
const defaultObserverConfigName = "observer-config"
const defaultObserverResultDetailConfigName = "verify-result-detail"
const logLevelEnvKey = "LOG_LEVEL"
const k8sLogLevelEnvKey = "K8S_MANIFEST_SIGSTORE_LOG_LEVEL"

// const ImageRefAnnotationKey = "cosign.sigstore.dev/imageRef"

const VerifyResourceViolationLabel = "integrityshield.io/verifyResourceViolation"
const VerifyResourceIgnoreLabel = "integrityshield.io/verifyResourceIgnored"

type Observer struct {
	APIResources []groupResource

	dynamicClient dynamic.Interface
}

// type TargetResourceConfig struct {
// 	// TargetResources          []groupResourceWithTargetNS        `json:"targetResouces"`
// 	IgnoreFields k8smanifest.ObjectFieldBindingList `json:"ignoreFields,omitempty"`
// 	// KeyConfigs               []KeyConfig                        `json:"keyConfigs"`
// 	// ResourceProvenanceConfig ResourceProvenanceConfig `json:"resourceProvenanceConfig,omitempty"`
// }

// Observer Config
type ObserverConfig struct {
	TargetConstraints      Rule   `json:"targetConstraints,omitempty"`
	ExportDetailResult     bool   `json:"exportDetailResult,omitempty"`
	ResultDetailConfigName string `json:"resultDetailConfigName,omitempty"`
	ResultDetailConfigKey  string `json:"resultDetailConfigKey,omitempty"`
}

type Rule struct {
	Match   []string `json:"match,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}

// Observer Result Detail
type VerifyResultDetail struct {
	Time                 string                            `json:"time"`
	Namespace            string                            `json:"namespace"`
	Name                 string                            `json:"name"`
	Kind                 string                            `json:"kind"`
	ApiGroup             string                            `json:"apiGroup"`
	ApiVersion           string                            `json:"apiVersion"`
	Error                bool                              `json:"error"`
	Message              string                            `json:"message"`
	Violation            bool                              `json:"violation"`
	VerifyResourceResult *k8smanifest.VerifyResourceResult `json:"verifyResourceResult"`
}
type ConstraintResult struct {
	ConstraintName  string               `json:"constraintName"`
	Violation       bool                 `json:"violation"`
	TotalViolations int                  `json:"totalViolations"`
	Results         []VerifyResultDetail `json:"results"`
}

type ObservationDetailResults struct {
	ConstraintResults []ConstraintResult `json:"constraintResults"`
}

// groupResource contains the APIGroup and APIResource
type groupResource struct {
	APIGroup    string             `json:"apiGroup"`
	APIVersion  string             `json:"apiVersion"`
	APIResource metav1.APIResource `json:"resource"`
}

type groupResourceWithTargetNS struct {
	groupResource    `json:""`
	TargetNamespaces []string `json:"targetNamespace"`
}

var logLevelMap = map[string]log.Level{
	"panic": log.PanicLevel,
	"fatal": log.FatalLevel,
	"error": log.ErrorLevel,
	"warn":  log.WarnLevel,
	"info":  log.InfoLevel,
	"debug": log.DebugLevel,
	"trace": log.TraceLevel,
}

func NewObserver() *Observer {
	insp := &Observer{}
	return insp
}

func (self *Observer) Init() error {
	log.Info("init Observer....")
	kubeconf, _ := kubeutil.GetKubeConfig()

	var err error

	err = self.getAPIResources(kubeconf)
	if err != nil {
		return err
	}

	dynamicClient, err := dynamic.NewForConfig(kubeconf)
	if err != nil {
		return err
	}
	self.dynamicClient = dynamicClient

	// log
	if os.Getenv("LOG_FORMAT") == "json" {
		log.SetFormatter(&log.JSONFormatter{TimestampFormat: time.RFC3339Nano})
	}
	logLevelStr := os.Getenv(logLevelEnvKey)
	if logLevelStr == "" {
		logLevelStr = "info"
	}
	logLevel, ok := logLevelMap[logLevelStr]
	if !ok {
		logLevel = log.InfoLevel
	}
	os.Setenv(k8sLogLevelEnvKey, logLevelStr)
	log.SetLevel(logLevel)
	return nil
}

func (self *Observer) Run() {
	// load config -> requestHandlerConfig
	rhconfig, err := ishield.LoadRequestHandlerConfig()
	if err != nil {
		log.Error("Failed to load RequestHandlerConfig; err: ", err.Error())
	}
	// load observer config
	tcconfig, err := loadObserverConfig()
	if err != nil {
		log.Error("Failed to load Observer config; err: ", err.Error())
	}
	// load constraints
	constraints, err := self.loadConstraints()
	if err != nil {
		log.Error("Failed to load constraints; err: ", err.Error())
	}
	// ObservationDetailResults
	var constraintResults []ConstraintResult
	for _, constraint := range constraints {
		constraintName := constraint.Parameters.ConstraintName
		var violations []vrres.VerifyResult
		var nonViolations []vrres.VerifyResult
		narrowedGVKList := self.getPossibleProtectedGVKs(constraint.Match)
		log.Debug("narrowedGVKList", narrowedGVKList)
		ignoreFields := constraint.Parameters.IgnoreFields
		secrets := constraint.Parameters.KeyConfigs
		if narrowedGVKList == nil {
			log.Info("there is no resources to observe in the constraint:", constraint.Parameters.ConstraintName)
			return
		}
		// get all resources of extracted GVKs
		resources := []unstructured.Unstructured{}
		for _, gResource := range narrowedGVKList {
			tmpResources, _ := self.getAllResoucesByGroupResource(gResource)
			resources = append(resources, tmpResources...)
		}

		// check all resources by verifyResource
		ignoreFields = append(ignoreFields, rhconfig.RequestFilterProfile.IgnoreFields...)
		results := ObserveResources(resources, constraint.Parameters.ImageRef, ignoreFields, secrets)
		for _, res := range results {
			// simple result

			if res.Violation {
				vres := vrres.VerifyResult{
					Namespace:  res.Namespace,
					Name:       res.Name,
					Kind:       res.Kind,
					ApiGroup:   res.ApiGroup,
					ApiVersion: res.ApiVersion,
					Result:     res.Message,
				}
				violations = append(violations, vres)
			} else {
				vres := vrres.VerifyResult{
					Namespace:  res.Namespace,
					Name:       res.Name,
					Kind:       res.Kind,
					ApiGroup:   res.ApiGroup,
					ApiVersion: res.ApiVersion,
					Signer:     res.VerifyResourceResult.Signer,
					SigRef:     res.VerifyResourceResult.SigRef,
					SignedTime: res.VerifyResourceResult.SignedTime,
					Result:     res.Message,
				}
				nonViolations = append(nonViolations, vres)
			}
			log.WithFields(log.Fields{
				"constraintName": constraintName,
				"violation":      res.Violation,
				"kind":           res.Kind,
				"name":           res.Name,
				"namespace":      res.Namespace,
			}).Info(res.Message)
		}
		// summarize results
		var violated bool
		if len(violations) != 0 {
			violated = true
		} else {
			violated = false
		}
		count := len(violations)

		vrr := vrres.VerifyResourceStatusSpec{
			ConstraintName:  constraintName,
			Violation:       violated,
			TotalViolations: count,
			Violations:      violations,
			NonViolations:   nonViolations,
			ObservationTime: time.Now().Format(timeFormat),
		}

		// check if targeted constraint
		ignored := checkIfInscopeConstraint(constraintName, tcconfig.TargetConstraints)

		// export VerifyResult
		_ = exportVerifyResult(vrr, ignored, violated)
		// VerifyResultDetail
		cres := ConstraintResult{
			ConstraintName:  constraintName,
			Results:         results,
			Violation:       violated,
			TotalViolations: count,
		}
		constraintResults = append(constraintResults, cres)
	}

	// export ConstraintResult
	res := ObservationDetailResults{
		ConstraintResults: constraintResults,
	}
	_ = exportResultDetail(res, tcconfig)
	return
}

func checkIfInscopeConstraint(constraintName string, tcconfig Rule) bool {
	ignored := false
	if len(tcconfig.Match) != 0 {
		match := false
		for _, p := range tcconfig.Match {
			included := MatchPattern(p, constraintName)
			if included {
				match = true
			}
		}
		if match {
			ignored = false
		} else {
			ignored = true
		}
	}
	if !ignored && len(tcconfig.Exclude) != 0 {
		match := false
		for _, p := range tcconfig.Exclude {
			excluded := MatchPattern(p, constraintName)
			if excluded {
				match = true
			}
		}
		if match {
			ignored = true
		} else {
			ignored = false
		}
	}
	return ignored
}

func exportVerifyResult(vrr vrres.VerifyResourceStatusSpec, ignored bool, violated bool) error {
	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		log.Error(err)
		return err
	}
	clientset, err := vrresclient.NewForConfig(config)
	if err != nil {
		log.Error(err)
		return err
	}
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		namespace = defaultPodNamespace
	}

	// label
	vv := "false"
	iv := "false"
	if violated {
		vv = "true"
	}
	if ignored {
		iv = "true"
	}
	labels := map[string]string{
		VerifyResourceViolationLabel: vv,
		VerifyResourceIgnoreLabel:    iv,
	}

	obj, err := clientset.VerifyResourceStatuses(namespace).Get(context.Background(), vrr.ConstraintName, metav1.GetOptions{})
	if err != nil || obj == nil {
		log.Info("creating new VerifyResourceStatus resource...")
		newVRR := &vrres.VerifyResourceStatus{
			ObjectMeta: metav1.ObjectMeta{
				Name: vrr.ConstraintName,
			},
			Spec: vrr,
		}

		newVRR.Labels = labels
		_, err = clientset.VerifyResourceStatuses(namespace).Create(context.Background(), newVRR, metav1.CreateOptions{})
		if err != nil {
			log.Error("failed to create VerifyResourceStatuses:", err.Error())
			return err
		}
	} else {
		log.Info("updating VerifyResourceStatuses resource...")
		obj.Spec = vrr
		obj.Labels = labels
		_, err = clientset.VerifyResourceStatuses(namespace).Update(context.Background(), obj, metav1.UpdateOptions{})
		if err != nil {
			log.Error("failed to update VerifyResourceStatuses:", err.Error())
			return err
		}
	}
	return nil
}

func exportResultDetail(results ObservationDetailResults, oconfig ObserverConfig) error {
	if !oconfig.ExportDetailResult {
		return nil
	}
	if len(results.ConstraintResults) == 0 {
		log.Info("no observation results")
		return nil
	}
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		namespace = defaultPodNamespace
	}
	configName := oconfig.ResultDetailConfigName
	if configName == "" {
		configName = defaultObserverResultDetailConfigName
	}
	configKey := oconfig.ResultDetailConfigKey
	if configKey == "" {
		configKey = defaultConfigKeyInConfigMap
	}

	// load
	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		return nil
	}
	clientset, err := kubeclient.NewForConfig(config)
	if err != nil {
		log.Error(err)
		return nil
	}
	cm, err := clientset.CoreV1().ConfigMaps(namespace).Get(context.Background(), configName, metav1.GetOptions{})
	if err != nil {
		// create
		log.Info("creating new configmap to store verify result...", configName)
		newcm := &v1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name: configName,
			},
		}
		resByte, _ := json.Marshal(results)
		newcm.Data = map[string]string{
			configKey: string(resByte),
		}
		_, err := clientset.CoreV1().ConfigMaps(namespace).Create(context.Background(), newcm, metav1.CreateOptions{})
		if err != nil {
			log.Error("failed to create configmap", err.Error())
			return err
		}
		return nil
	} else {
		// update
		log.Info("updating configmap ...", configName)
		resByte, _ := json.Marshal(results)
		cm.Data = map[string]string{
			configKey: string(resByte),
		}
		_, err := clientset.CoreV1().ConfigMaps(namespace).Update(context.Background(), cm, metav1.UpdateOptions{})
		if err != nil {
			log.Error("failed to update configmap", err.Error())
			return err
		}
	}
	return nil
}

func (self *Observer) getAPIResources(kubeconfig *rest.Config) error {
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(kubeconfig)
	if err != nil {
		return err
	}

	apiResourceLists, err := discoveryClient.ServerPreferredResources()
	if err != nil {
		return err
	}

	resources := []groupResource{}
	for _, apiResourceList := range apiResourceLists {
		if len(apiResourceList.APIResources) == 0 {
			continue
		}
		gv, err := schema.ParseGroupVersion(apiResourceList.GroupVersion)
		if err != nil {
			continue
		}
		for _, resource := range apiResourceList.APIResources {
			if len(resource.Verbs) == 0 {
				continue
			}
			resources = append(resources, groupResource{
				APIGroup:    gv.Group,
				APIVersion:  gv.Version,
				APIResource: resource,
			})
		}
	}
	self.APIResources = resources
	return nil
}

func (self *Observer) getAllResoucesByGroupResource(gResourceWithTargetNS groupResourceWithTargetNS) ([]unstructured.Unstructured, error) {
	var resources []unstructured.Unstructured
	var err error
	gResource := gResourceWithTargetNS.groupResource
	targetNSs := gResourceWithTargetNS.TargetNamespaces
	namespaced := gResource.APIResource.Namespaced
	gvr := schema.GroupVersionResource{
		Group:    gResource.APIGroup,
		Version:  gResource.APIVersion,
		Resource: gResource.APIResource.Name,
	}

	var tmpResourceList *unstructured.UnstructuredList
	if namespaced {
		for _, ns := range targetNSs {
			tmpResourceList, err = self.dynamicClient.Resource(gvr).Namespace(ns).List(context.Background(), metav1.ListOptions{})
			if err != nil {
				log.Error("failed to get tmpResourceList:", err.Error())
				break
			}
			resources = append(resources, tmpResourceList.Items...)
		}

	} else {
		tmpResourceList, err = self.dynamicClient.Resource(gvr).List(context.Background(), metav1.ListOptions{})
		resources = append(resources, tmpResourceList.Items...)
	}
	if err != nil {
		// ignore RBAC error - IShield SA
		log.Error("RBAC error when listing resources; error:", err.Error())
		return []unstructured.Unstructured{}, nil
	}
	return resources, nil
}

func loadObserverConfig() (ObserverConfig, error) {
	var empty ObserverConfig
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		namespace = defaultPodNamespace
	}
	configName := os.Getenv("OBSERVER_CONFIG_NAME")
	if configName == "" {
		configName = defaultObserverConfigName
	}
	configKey := os.Getenv("OBSERVER_CONFIG_KEY")
	if configKey == "" {
		configKey = defaultConfigKeyInConfigMap
	}

	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		return empty, err
	}
	clientset, err := kubeclient.NewForConfig(config)
	if err != nil {
		log.Error(err)
		return empty, err
	}
	cm, err := clientset.CoreV1().ConfigMaps(namespace).Get(context.Background(), configName, metav1.GetOptions{})
	if err != nil {
		return empty, errors.Wrap(err, fmt.Sprintf("failed to get a configmap `%s` in `%s` namespace", configName, namespace))
	}
	cfgBytes, found := cm.Data[configKey]
	if !found {
		return empty, errors.New(fmt.Sprintf("`%s` is not found in configmap", configKey))
	}
	var tr *ObserverConfig
	err = yaml.Unmarshal([]byte(cfgBytes), &tr)
	if err != nil {
		return empty, errors.Wrap(err, fmt.Sprintf("failed to unmarshal config.yaml into %T", tr))
	}
	if tr == nil {
		return empty, nil
	}
	return *tr, nil
}

func LoadKeySecret(keySecertNamespace, keySecertName string) (string, error) {
	obj, err := kubeutil.GetResource("v1", "Secret", keySecertNamespace, keySecertName)
	if err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("failed to get a secret `%s` in `%s` namespace", keySecertName, keySecertNamespace))
	}
	objBytes, _ := json.Marshal(obj.Object)
	var secret v1.Secret
	_ = json.Unmarshal(objBytes, &secret)
	keyDir := fmt.Sprintf("/tmp/%s/%s/", keySecertNamespace, keySecertName)
	log.Debug("keyDir", keyDir)
	sumErr := []string{}
	keyPath := ""
	for fname, keyData := range secret.Data {
		os.MkdirAll(keyDir, os.ModePerm)
		fpath := filepath.Join(keyDir, fname)
		err = ioutil.WriteFile(fpath, keyData, 0644)
		if err != nil {
			sumErr = append(sumErr, err.Error())
			continue
		}
		keyPath = fpath
		break
	}
	if keyPath == "" && len(sumErr) > 0 {
		return "", errors.New(fmt.Sprintf("failed to save secret data as a file; %s", strings.Join(sumErr, "; ")))
	}
	if keyPath == "" {
		return "", errors.New(fmt.Sprintf("no key files are found in the secret `%s` in `%s` namespace", keySecertName, keySecertNamespace))
	}

	return keyPath, nil
}

//
// Constraint
//

type ConstraintSpec struct {
	Match      MatchCondition               `json:"match,omitempty"`
	Parameters k8smnfconfig.ParameterObject `json:"parameters,omitempty"`
}

type MatchCondition struct {
	Kinds              []Kinds               `json:"kinds,omitempty"`
	Namespaces         []string              `json:"namespaces,omitempty"`
	ExcludedNamespaces []string              `json:"excludedNamespaces,omitempty"`
	LabelSelector      *metav1.LabelSelector `json:"labelSelector,omitempty"`
	NamespaceSelector  *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
}

type Kinds struct {
	Kinds     []string `json:"kinds,omitempty"`
	ApiGroups []string `json:"apiGroups,omitempty"`
}

func (self *Observer) loadConstraints() ([]ConstraintSpec, error) {
	gvr := schema.GroupVersionResource{
		Group:    "constraints.gatekeeper.sh",
		Version:  "v1beta1",
		Resource: "manifestintegrityconstraint",
	}
	constraintList, err := self.dynamicClient.Resource(gvr).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	micList := []ConstraintSpec{}
	for _, unstructed := range constraintList.Items {
		log.Debug("unstructed.Object", unstructed.Object)
		var mic ConstraintSpec
		spec, ok := unstructed.Object["spec"]
		if !ok {
			fmt.Println("failed to get spec in constraint", unstructed.GetName())
		}
		jsonStr, err := json.Marshal(spec)
		if err != nil {
			fmt.Println(err)
		}
		if err := json.Unmarshal(jsonStr, &mic); err != nil {
			fmt.Println(err)
		}
		log.Debug("ManigestIntegrityConstraint:", mic)
		micList = append(micList, mic)
	}
	return micList, nil
}

func (self *Observer) getPossibleProtectedGVKs(match MatchCondition) []groupResourceWithTargetNS {
	possibleProtectedGVKs := []groupResourceWithTargetNS{}
	for _, apiResource := range self.APIResources {
		matched, tmpGvks := checkIfRuleMatchWithGVK(match, apiResource)
		if matched {
			possibleProtectedGVKs = append(possibleProtectedGVKs, tmpGvks...)
			break
		}
	}
	return possibleProtectedGVKs
}

// TODO: check logic
func checkIfRuleMatchWithGVK(match MatchCondition, apiResource groupResource) (bool, []groupResourceWithTargetNS) {
	possibleProtectedGVKs := []groupResourceWithTargetNS{}
	// TODO: support "LabelSelector"
	if len(match.Kinds) == 0 {
		return false, nil
	}
	matched := false
	for _, kinds := range match.Kinds {
		kmatch := false
		agmatch := false
		if len(kinds.ApiGroups) != 0 {
			agmatch = Contains(kinds.ApiGroups, apiResource.APIGroup)
		} else {
			agmatch = true
		}
		if len(kinds.ApiGroups) != 0 {
			kmatch = Contains(kinds.Kinds, apiResource.APIResource.Kind)
		} else {
			kmatch = true
		}
		if kmatch && agmatch {
			matched = true
			namespaces := match.Namespaces
			if match.NamespaceSelector != nil {
				labeledNS := getLabelMatchedNamespace(match.NamespaceSelector)
				namespaces = append(namespaces, labeledNS...)
			}
			possibleProtectedGVKs = append(possibleProtectedGVKs, groupResourceWithTargetNS{
				groupResource:    apiResource,
				TargetNamespaces: namespaces,
			})
		}
	}
	log.WithFields(log.Fields{
		"matched":               matched,
		"possibleProtectedGVKs": possibleProtectedGVKs,
	}).Debug("check match condition")
	return matched, possibleProtectedGVKs
}

func Contains(pattern []string, value string) bool {
	for _, p := range pattern {
		if p == value {
			return true
		}
	}
	return false
}

func getLabelMatchedNamespace(labelSelector *metav1.LabelSelector) []string {
	matchedNs := []string{}
	if labelSelector == nil {
		return []string{}
	}
	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		return []string{}
	}
	clientset, err := kubeclient.NewForConfig(config)
	if err != nil {
		log.Error(err)
		return []string{}
	}
	namespaces, err := clientset.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Errorf("failed to list a namespace:`%s`", err.Error())
		return []string{}
	}
	selector, err := metav1.LabelSelectorAsSelector(labelSelector)
	if err != nil {
		log.Errorf("failed to convert the LabelSelector api type into a struct that implements labels.Selector; %s", err.Error())
		return []string{}
	}

	for _, ns := range namespaces.Items {
		labelsMap := ns.GetLabels()
		labelsSet := labels.Set(labelsMap)
		matched := selector.Matches(labelsSet)
		if matched {
			matchedNs = append(matchedNs, ns.Name)
		}
	}
	return matchedNs
}

func MatchPattern(pattern, value string) bool {
	if pattern == "" {
		return true
	} else if pattern == "*" {
		return true
	} else if pattern == "-" && value == "" {
		return true
	} else if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(value, strings.TrimRight(pattern, "*"))
	} else if pattern == value {
		return true
	} else {
		return false
	}
}
