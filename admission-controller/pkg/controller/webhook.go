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
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	acconfig "github.com/IBM/integrity-shield/admission-controller/pkg/config"
	"github.com/IBM/integrity-shield/integrity-shield-server/pkg/shield"
	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubeclient "k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const defaultConfigKeyInConfigMap = "config.yaml"
const defaultPodNamespace = "k8s-manifest-sigstore"
const defaultControllerConfigName = "admission-controller-config"
const logLevelEnvKey = "LOG_LEVEL"

const (
	EventTypeAnnotationKey       = "integrityshield.io/eventType"
	EventTypeAnnotationValueDeny = "deny"
)

var logLevelMap = map[string]log.Level{
	"panic": log.PanicLevel,
	"fatal": log.FatalLevel,
	"error": log.ErrorLevel,
	"warn":  log.WarnLevel,
	"info":  log.InfoLevel,
	"debug": log.DebugLevel,
	"trace": log.TraceLevel,
}

type AccumulatedResult struct {
	Allow   bool
	Message string
}

func init() {
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

	log.SetLevel(logLevel)
}

func ProcessRequest(req admission.Request) admission.Response {
	// load ac2 config
	config, err := loadAdmissionControllerConfig()
	if err != nil {
		log.Errorf("failed to load admission controller config; %s", err.Error())
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
		isMatched := matchCheck(req, constraint.Spec.Match)
		if !isMatched {
			r := shield.ResultFromRequestHandler{
				Allow:   true,
				Message: "not protected",
				Profile: constraint.Name,
			}
			results = append(results, r)
			continue
		}

		// pick parameters from constaint
		paramObj := GetParametersFromConstraint(constraint.Spec)

		// call request handler & receive result from request handler (allow, message)
		useRemote, _ := strconv.ParseBool(os.Getenv("USE_REMOTE_HANDLER"))
		r := shield.RequestHandlerController(useRemote, req, paramObj)
		// r := handler.RequestHandler(req, paramObj)

		r.Profile = constraint.Name
		results = append(results, *r)
	}

	// accumulate results from constraints
	ar := getAccumulatedResult(results)

	// mode check
	isDetectMode := acconfig.CheckIfDetectOnly(config.Mode)
	if !ar.Allow && isDetectMode {
		ar.Allow = true
		msg := "allowed by detection mode: " + ar.Message
		ar.Message = msg
	}

	// TODO: generate events
	if config.SideEffect.CreateDenyEvent {
		_ = createOrUpdateEvent(req, ar)
	}
	// update status
	if config.SideEffect.UpdateMIPStatusForDeniedRequest {
		updateConstraints(isDetectMode, req, results)
	}

	// log
	log.WithFields(log.Fields{
		"namespace": req.Namespace,
		"name":      req.Name,
		"kind":      req.Kind.Kind,
		"operation": req.Operation,
		"allow":     ar.Allow,
	}).Info(ar.Message)

	// return admission response
	if ar.Allow {
		return admission.Allowed(ar.Message)
	} else {
		return admission.Denied(ar.Message)
	}
}

func loadAdmissionControllerConfig() (*acconfig.AdmissionControllerConfig, error) {
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
	var sc *acconfig.AdmissionControllerConfig
	err = yaml.Unmarshal([]byte(cfgBytes), &sc)
	if err != nil {
		return sc, errors.Wrap(err, fmt.Sprintf("failed to unmarshal config.yaml into %T", sc))
	}
	return sc, nil
}

func getAccumulatedResult(results []shield.ResultFromRequestHandler) *AccumulatedResult {
	denyMessages := []string{}
	allowMessages := []string{}
	accumulatedRes := &AccumulatedResult{}
	for _, result := range results {
		if !result.Allow {
			msg := "[" + result.Profile + "]" + result.Message
			denyMessages = append(denyMessages, msg)
		} else {
			msg := "[" + result.Profile + "]" + result.Message
			allowMessages = append(allowMessages, msg)
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

func createOrUpdateEvent(req admission.Request, ar *AccumulatedResult) error {
	// no event is generated for allowed request
	if ar.Allow {
		return nil
	}

	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		return err
	}
	client, err := kubeclient.NewForConfig(config)
	if err != nil {
		return err
	}

	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		namespace = defaultPodNamespace
	}
	gv := schema.GroupVersion{Group: req.Kind.Group, Version: req.Kind.Version}
	evtNamespace := req.Namespace
	if evtNamespace == "" {
		evtNamespace = namespace
	}
	involvedObject := corev1.ObjectReference{
		Namespace:  req.Namespace,
		APIVersion: gv.String(),
		Kind:       req.Kind.Kind,
		Name:       req.Name,
	}
	evtName := fmt.Sprintf("ishield-deny-%s-%s-%s", strings.ToLower(string(req.Operation)), strings.ToLower(req.Kind.Kind), req.Name)
	sourceName := "IntegrityShield"

	now := time.Now()
	evt := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      evtName,
			Namespace: evtNamespace,
			Annotations: map[string]string{
				EventTypeAnnotationKey: EventTypeAnnotationValueDeny,
			},
		},
		InvolvedObject:      involvedObject,
		Type:                sourceName,
		Source:              v1.EventSource{Component: sourceName},
		ReportingController: sourceName,
		ReportingInstance:   evtName,
		Action:              evtName,
		Reason:              "Deny",
		FirstTimestamp:      metav1.NewTime(now),
	}
	isExistingEvent := false
	current, getErr := client.CoreV1().Events(evtNamespace).Get(context.Background(), evtName, metav1.GetOptions{})
	if current != nil && getErr == nil {
		isExistingEvent = true
		evt = current
	}

	tmpMessage := ar.Message
	// Event.Message can have 1024 chars at most
	if len(tmpMessage) > 1024 {
		tmpMessage = tmpMessage[:950] + " ... Trimmed. `Event.Message` can have 1024 chars at maximum."
	}
	evt.Message = tmpMessage
	evt.Count = evt.Count + 1
	evt.EventTime = metav1.NewMicroTime(now)
	evt.LastTimestamp = metav1.NewTime(now)

	if isExistingEvent {
		_, err = client.CoreV1().Events(evtNamespace).Update(context.Background(), evt, metav1.UpdateOptions{})
	} else {
		_, err = client.CoreV1().Events(evtNamespace).Create(context.Background(), evt, metav1.CreateOptions{})
	}
	if err != nil {
		log.Errorf("failed to generate deny event; %s", err.Error())
		return err
	}

	log.WithFields(log.Fields{
		"namespace": req.Namespace,
		"name":      req.Name,
		"kind":      req.Kind.Kind,
		"operation": req.Operation,
	}).Debug("Deny event is generated:", evtName)

	return nil
}
