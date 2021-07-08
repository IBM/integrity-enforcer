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

package shield

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	k8smnfconfig "github.com/IBM/integrity-shield/integrity-shield-server/pkg/config"
	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/mapnode"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	kubeclient "k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const remoteRequestHandlerURL = "https://integrity-shield-api.k8s-manifest-sigstore.svc:8123/api/request"
const defaultConfigKeyInConfigMap = "config.yaml"
const defaultPodNamespace = "k8s-manifest-sigstore"
const defaultHandlerConfigMapName = "request-handler-config"

func RequestHandlerController(remote bool, req admission.Request, paramObj *k8smnfconfig.ParameterObject) *ResultFromRequestHandler {
	r := &ResultFromRequestHandler{}
	if remote {
		// http call to remote request handler service
		input := &RemoteRequestHandlerInputMap{
			Request:   req,
			Parameter: *paramObj,
		}

		inputjson, _ := json.Marshal(input)
		transCfg := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: transCfg}
		res, err := client.Post(remoteRequestHandlerURL, "application/json", bytes.NewBuffer([]byte(inputjson)))
		if err != nil {
			log.Error("Error reported from Remote RequestHandler", err.Error())
			return &ResultFromRequestHandler{
				Allow:   true,
				Message: "error but allow for development",
			}
		}
		if res.StatusCode != 200 {
			log.Error("Error reported from Remote RequestHandler: statusCode is not 200")
			return &ResultFromRequestHandler{
				Allow:   true,
				Message: "error but allow for development",
			}
		}
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			log.Error("error: fail to read body: ", err)
			return &ResultFromRequestHandler{
				Allow:   true,
				Message: "error but allow for development",
			}
		}
		err = json.Unmarshal([]byte(string(body)), &r)
		if err != nil {
			log.Error("error: fail to Unmarshal: ", err)
			return &ResultFromRequestHandler{
				Allow:   true,
				Message: "error but allow for development",
			}
		}
		log.Debug("Response from remote request handler ", r)
		return r
	} else {
		// local request handler
		r = RequestHandler(req, paramObj)
	}
	return r
}

func RequestHandler(req admission.Request, paramObj *k8smnfconfig.ParameterObject) *ResultFromRequestHandler {
	// unmarshal admission request object
	// load Resource from Admission request
	var resource unstructured.Unstructured
	objectBytes := req.AdmissionRequest.Object.Raw
	err := json.Unmarshal(objectBytes, &resource)
	if err != nil {
		log.Errorf("failed to Unmarshal a requested object into %T; %s", resource, err.Error())
		return &ResultFromRequestHandler{
			Allow:   true,
			Message: "error but allow for development",
		}
	}

	// load request handler config
	rhconfig, err := loadRequestHandlerConfig()
	if err != nil {
		log.Errorf("failed to load shield config", err.Error())
		return &ResultFromRequestHandler{
			Allow:   true,
			Message: "error but allow for development",
		}
	}

	// setup log
	logger := k8smnfconfig.NewLogger(rhconfig.Log.Level, req)

	commonSkipUserMatched := false
	skipObjectMatched := false
	if rhconfig != nil {
		//filter by user listed in common profile
		commonSkipUserMatched = rhconfig.RequestFilterProfile.SkipUsers.Match(resource, req.AdmissionRequest.UserInfo.Username)
		// ignore object
		skipObjectMatched = rhconfig.RequestFilterProfile.SkipObjects.Match(resource)
	}

	// Proccess with parameter
	//filter by user
	skipUserMatched := paramObj.SkipUsers.Match(resource, req.AdmissionRequest.UserInfo.Username)

	//check scope
	inScopeObjMatched := paramObj.InScopeObjects.Match(resource)

	// mutation check
	if isUpdateRequest(req.AdmissionRequest.Operation) {
		ignoreFields := getMatchedIgnoreFields(paramObj.IgnoreFields, rhconfig.RequestFilterProfile.IgnoreFields, resource)
		mutated, err := mutationCheck(req.AdmissionRequest.OldObject.Raw, req.AdmissionRequest.Object.Raw, ignoreFields)
		if err != nil {
			logger.Errorf("failed to check mutation", err.Error())
			return &ResultFromRequestHandler{
				Allow:   true,
				Message: "error but allow for development",
			}
		}
		if !mutated {
			return &ResultFromRequestHandler{
				Allow:   true,
				Message: "no mutation found",
			}
		}
	}

	allow := true
	message := ""
	if skipUserMatched || commonSkipUserMatched {
		allow = true
		message = "ignore user config matched"
	} else if !inScopeObjMatched {
		allow = true
		message = "this resource is not in scope of verification"
	} else if skipObjectMatched {
		allow = true
		message = "this resource is not in scope of verification"
	} else {
		// get verifyOption and imageRef from Parameter
		imageRef := paramObj.ImageRef
		// prepare local key for verifyResource
		keyPath := ""
		if paramObj.KeySecertName != "" {
			keyPath, _ = k8smnfconfig.LoadKeySecret(paramObj.KeySecertNamespace, paramObj.KeySecertName)
		}
		vo := setVerifyOption(&paramObj.VerifyOption, rhconfig)
		// call VerifyResource with resource, verifyOption, keypath, imageRef
		result, err := k8smanifest.VerifyResource(resource, imageRef, keyPath, vo)
		logger.Debug("VerifyResource: ", result)
		if err != nil {
			logger.Errorf("failed to check a requested resource; %s", err.Error())
			return &ResultFromRequestHandler{
				Allow:   true,
				Message: "error but allow for development",
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
		Allow:   allow,
		Message: message,
	}

	// log
	// logMsg := fmt.Sprintf("%s %s %s : %s %s", req.Kind.Kind, req.Name, req.Operation, strconv.FormatBool(r.Allow), r.Message)
	logger.Debug("RequestHandler: ", r)

	return r
}

type ResultFromRequestHandler struct {
	Allow   bool   `json:"allow"`
	Message string `json:"message"`
}

func isUpdateRequest(operation v1.Operation) bool {
	return (operation == v1.Update)
}

func getMatchedIgnoreFields(pi, ci k8smanifest.ObjectFieldBindingList, resource unstructured.Unstructured) []string {
	var allIgnoreFields []string
	_, fields := pi.Match(resource)
	_, commonfields := ci.Match(resource)
	allIgnoreFields = append(allIgnoreFields, fields...)
	allIgnoreFields = append(allIgnoreFields, commonfields...)
	return allIgnoreFields
}

func mutationCheck(rawOldObject, rawObject []byte, IgnoreFields []string) (bool, error) {
	var oldObject *mapnode.Node
	var newObject *mapnode.Node
	mask := []string{
		"metadata.annotations.namespace",
		"metadata.annotations.kubectl.\"kubernetes.io/last-applied-configuration\"",
		"metadata.annotations.deprecated.daemonset.template.generation",
		"metadata.creationTimestamp",
		"metadata.uid",
		"metadata.generation",
		"metadata.managedFields",
		"metadata.selfLink",
		"metadata.resourceVersion",
		"status",
	}
	if v, err := mapnode.NewFromBytes(rawObject); err != nil || v == nil {
		return false, err
	} else {
		v = v.Mask(mask)
		obj := v.ToMap()
		newObject, _ = mapnode.NewFromMap(obj)
	}
	if v, err := mapnode.NewFromBytes(rawOldObject); err != nil || v == nil {
		return false, err
	} else {
		v = v.Mask(mask)
		oldObj := v.ToMap()
		oldObject, _ = mapnode.NewFromMap(oldObj)
	}
	// diff
	dr := oldObject.Diff(newObject)
	if dr.Size() == 0 {
		return false, nil
	}
	// ignoreField check
	unfiltered := &mapnode.DiffResult{}
	if dr != nil && dr.Size() > 0 {
		_, unfiltered, _ = dr.Filter(IgnoreFields)
	}
	if unfiltered.Size() == 0 {
		return false, nil
	}
	return true, nil
}

func setVerifyOption(vo *k8smanifest.VerifyOption, config *k8smnfconfig.RequestHandlerConfig) *k8smanifest.VerifyOption {
	if config == nil {
		return vo
	}
	fields := k8smanifest.ObjectFieldBindingList{}
	fields = append(fields, vo.IgnoreFields...)
	fields = append(fields, config.RequestFilterProfile.IgnoreFields...)
	vo.IgnoreFields = fields
	// log.Info("[DEBUG] setVerifyOption: ", vo)
	return vo
}

func loadRequestHandlerConfig() (*k8smnfconfig.RequestHandlerConfig, error) {
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		namespace = defaultPodNamespace
	}
	configName := os.Getenv("REQUEST_HANDLER_CONFIG_NAME")
	if configName == "" {
		configName = defaultHandlerConfigMapName
	}
	configKey := os.Getenv("REQUEST_HANDLER__CONFIG_KEY")
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
	var sc *k8smnfconfig.RequestHandlerConfig
	err = yaml.Unmarshal([]byte(cfgBytes), &sc)
	if err != nil {
		return sc, errors.Wrap(err, fmt.Sprintf("failed to unmarshal config.yaml into %T", sc))
	}
	// log.Info("[DEBUG] HandlerConfig: ", sc)
	return sc, nil
}

type RemoteRequestHandlerInputMap struct {
	Request   admission.Request            `json:"request,omitempty"`
	Parameter k8smnfconfig.ParameterObject `json:"parameters,omitempty"`
}
