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

package kubeutil

import (
	"bytes"
	// "context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/ghodss/yaml"
	"github.com/jonboulle/clockwork"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/jsonmergepatch"
	"k8s.io/apimachinery/pkg/util/mergepatch"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/resource"
	"k8s.io/client-go/dynamic"
	oapi "k8s.io/kube-openapi/pkg/util/proto"
	"k8s.io/kubectl/pkg/cmd/apply"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/scheme"
	"k8s.io/kubectl/pkg/util"
)

var (
	warningNoLastAppliedConfigAnnotation = "Warning: %[1]s apply should be used on resource created by either %[1]s create --save-config or %[1]s apply\n"
)

func DryRunCreate(objBytes []byte, namespace string) ([]byte, error) {
	config, err := GetKubeConfig()
	if err != nil {
		return nil, fmt.Errorf("Error in getting K8s config; %s", err.Error())
	}
	dyClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("Error in createging DynamicClient; %s", err.Error())
	}

	obj := &unstructured.Unstructured{}
	objJsonBytes, err := yaml.YAMLToJSON(objBytes)
	if err != nil {
		return nil, fmt.Errorf("Error in converting YamlToJson; %s", err.Error())
	}
	err = obj.UnmarshalJSON(objJsonBytes)
	if err != nil {
		return nil, fmt.Errorf("Error in Unmarshal into unstructured obj; %s", err.Error())
	}
	obj.SetName(fmt.Sprintf("%s-dry-run", obj.GetName()))

	gvk := obj.GroupVersionKind()
	gvr, _ := meta.UnsafeGuessKindToResource(gvk)
	gvClient := dyClient.Resource(gvr)

	var simObj *unstructured.Unstructured
	if namespace == "" {
		simObj, err = gvClient.Create(nil, obj, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
	} else {
		simObj, err = gvClient.Namespace(namespace).Create(nil, obj, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
	}
	if err != nil {
		return nil, fmt.Errorf("Error in createging resource; %s, gvk: %s", err.Error(), gvk)
	}
	simObjBytes, err := yaml.Marshal(simObj)
	if err != nil {
		return nil, fmt.Errorf("Error in converting ojb to yaml; %s", err.Error())
	}
	return simObjBytes, nil
}

func strategicMergePatch(objBytes []byte, namespace string) ([]byte, []byte, error) {
	config, err := GetKubeConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("Error in getting K8s config; %s", err.Error())
	}
	dyClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, nil, fmt.Errorf("Error in createging DynamicClient; %s", err.Error())
	}

	obj := &unstructured.Unstructured{}
	objJsonBytes, err := yaml.YAMLToJSON(objBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("Error in converting YamlToJson; %s", err.Error())
	}
	err = obj.UnmarshalJSON(objJsonBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("Error in Unmarshal into unstructured obj; %s", err.Error())
	}
	gvk := obj.GroupVersionKind()
	gvr, _ := meta.UnsafeGuessKindToResource(gvk)
	gvClient := dyClient.Resource(gvr)
	claimedNamespace := obj.GetNamespace()
	claimedName := obj.GetName()
	if namespace != "" && claimedNamespace != "" && namespace != claimedNamespace {
		return nil, nil, fmt.Errorf("namespace is not identical, requested: %s, defined in yaml: %s", namespace, claimedNamespace)
	}
	if namespace == "" && claimedNamespace != "" {
		namespace = claimedNamespace
	}

	var currentObj *unstructured.Unstructured
	if namespace == "" {
		currentObj, err = gvClient.Get(nil, claimedName, metav1.GetOptions{})
	} else {
		currentObj, err = gvClient.Namespace(namespace).Get(nil, claimedName, metav1.GetOptions{})
	}
	if err != nil && !errors.IsNotFound(err) {
		return nil, nil, fmt.Errorf("Error in getting current obj; %s", err.Error())
	}
	currentObjBytes, err := json.Marshal(currentObj)
	if err != nil {
		return nil, nil, fmt.Errorf("Error in converting current obj to json; %s", err.Error())
	}
	creator := scheme.Scheme
	mocObj, err := creator.New(gvk)
	if err != nil {
		return nil, nil, fmt.Errorf("Error in getting moc obj; %s", err.Error())
	}
	patchedBytes, err := strategicpatch.StrategicMergePatch(currentObjBytes, objJsonBytes, mocObj)
	if err != nil {
		return nil, nil, fmt.Errorf("Error in getting patched obj bytes; %s", err.Error())
	}
	return patchedBytes, currentObjBytes, nil
}

func StrategicMergePatch(objBytes, patchBytes []byte, namespace string) ([]byte, error) {
	config, err := GetKubeConfig()
	if err != nil {
		return nil, fmt.Errorf("Error in getting K8s config; %s", err.Error())
	}
	dyClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("Error in createging DynamicClient; %s", err.Error())
	}

	obj := &unstructured.Unstructured{}
	err = obj.UnmarshalJSON(objBytes)
	if err != nil {
		return nil, fmt.Errorf("Error in Unmarshal into unstructured obj; %s", err.Error())
	}
	gvk := obj.GroupVersionKind()
	gvr, _ := meta.UnsafeGuessKindToResource(gvk)
	gvClient := dyClient.Resource(gvr)
	claimedNamespace := obj.GetNamespace()
	claimedName := obj.GetName()
	if namespace != "" && claimedNamespace != "" && namespace != claimedNamespace {
		return nil, fmt.Errorf("namespace is not identical, requested: %s, defined in yaml: %s", namespace, claimedNamespace)
	}
	if namespace == "" && claimedNamespace != "" {
		namespace = claimedNamespace
	}

	var currentObj *unstructured.Unstructured
	if namespace == "" {
		currentObj, err = gvClient.Get(nil, claimedName, metav1.GetOptions{})
	} else {
		currentObj, err = gvClient.Namespace(namespace).Get(nil, claimedName, metav1.GetOptions{})
	}
	if err != nil && !errors.IsNotFound(err) {
		return nil, fmt.Errorf("Error in getting current obj; %s", err.Error())
	}
	currentObjBytes, err := json.Marshal(currentObj)
	if err != nil {
		return nil, fmt.Errorf("Error in converting current obj to json; %s", err.Error())
	}
	creator := scheme.Scheme
	mocObj, err := creator.New(gvk)
	if err != nil {
		return nil, fmt.Errorf("Error in getting moc obj; %s", err.Error())
	}
	patchJsonBytes, err := yaml.YAMLToJSON(patchBytes)
	if err != nil {
		return nil, fmt.Errorf("Error in converting patchBytes to json; %s", err.Error())
	}
	patchedBytes, err := strategicpatch.StrategicMergePatch(currentObjBytes, patchJsonBytes, mocObj)
	if err != nil {
		return nil, fmt.Errorf("Error in getting patched obj bytes; %s", err.Error())
	}
	return patchedBytes, nil
}

func GetApplyPatchBytes(objBytes []byte, namespace string) ([]byte, []byte, error) {
	obj := &unstructured.Unstructured{}
	objFileName := "/tmp/obj.yaml"
	err := ioutil.WriteFile(objFileName, objBytes, 0644)
	if err != nil {
		return nil, nil, fmt.Errorf("Error in creating objFile; %s", err.Error())
	}
	objJsonBytes, err := yaml.YAMLToJSON(objBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("Error in converting YamlToJson; %s", err.Error())
	}
	err = obj.UnmarshalJSON(objJsonBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("Error in Unmarshal into unstructured obj; %s", err.Error())
	}

	//fieldManager := "integrity-enforcer"

	kubeConfigFlags := genericclioptions.NewConfigFlags(true).WithDeprecatedPasswordFlag()
	matchVersionKubeConfigFlags := cmdutil.NewMatchVersionFlags(kubeConfigFlags)

	f := cmdutil.NewFactory(matchVersionKubeConfigFlags)
	validator, err := f.Validator(false)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to create Validator; %s", err)
	}
	dynamicClient, err := f.DynamicClient()
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to create dynamicClient; %s", err)
	}
	openApiSchema, err := f.OpenAPISchema()
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to create OpenAPISchema; %s", err)
	}
	filenameOptions := resource.FilenameOptions{
		Filenames: []string{objFileName},
	}
	builder := f.NewBuilder()
	r := builder.
		Unstructured().
		Schema(validator).
		ContinueOnError().
		NamespaceParam(namespace).DefaultNamespace().
		FilenameParam(true, &filenameOptions).
		LabelSelectorParam("").
		Flatten().
		Do()
	infos, err := r.Infos()
	if err != nil {
		return nil, nil, err
	}
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to get resource Infos; %s", err)
	}
	if len(infos) == 0 {
		return nil, nil, fmt.Errorf("No resource.Info is found")
	}

	info := infos[0]

	// helper := resource.NewHelper(info.Client, info.Mapping).DryRun(true)
	modified, err := util.GetModifiedConfiguration(info.Object, true, unstructured.UnstructuredJSONScheme)
	if err != nil {
		return nil, nil, cmdutil.AddSourceToErr(fmt.Sprintf("retrieving modified configuration from:\n%s\nfor:", info.String()), info.Source, err)
	}

	if err := info.Get(); err != nil {
		if errors.IsNotFound(err) {
			// creating a new resource by apply command.
			// pass
		} else {
			return nil, nil, fmt.Errorf("Failed to get object from server; %s", err)
		}
	}

	errout := bytes.NewBufferString("")

	metadata, _ := meta.Accessor(info.Object)
	annotationMap := metadata.GetAnnotations()
	if _, ok := annotationMap[corev1.LastAppliedConfigAnnotation]; !ok {
		fmt.Fprintf(errout, warningNoLastAppliedConfigAnnotation, "kubectl")
	}

	maxPatchRetry := 5
	patcher := &apply.Patcher{
		Mapping:       info.Mapping,
		Helper:        resource.NewHelper(info.Client, info.Mapping),
		DynamicClient: dynamicClient,
		Overwrite:     true,
		BackOff:       clockwork.NewRealClock(),
		Force:         true,
		Cascade:       true,
		Timeout:       0,
		GracePeriod:   0,
		OpenapiSchema: openApiSchema,
		Retries:       maxPatchRetry,
		ServerDryRun:  true,
	}

	//patchBytes, patchedObject, err := patcher.Patch(info.Object, modified, info.Source, namespace, info.Name, errout)
	patchBytes, patchedObject, err := patchSimple(patcher, info.Object, modified, info.Source, namespace, info.Name, errout)
	if err != nil {
		return nil, nil, cmdutil.AddSourceToErr(fmt.Sprintf("applying patch:\n%s\nto:\n%v\nfor:", patchBytes, info), info.Source, err)
	}
	info.Refresh(patchedObject, true)
	patched, _ := json.Marshal(patchedObject)
	//fmt.Println("debug 2: ", string(patched))

	return patchBytes, patched, nil
}

func patchSimple(p *apply.Patcher, obj runtime.Object, modified []byte, source, namespace, name string, errOut io.Writer) ([]byte, runtime.Object, error) {
	current, err := runtime.Encode(unstructured.UnstructuredJSONScheme, obj)
	if err != nil {
		return nil, nil, cmdutil.AddSourceToErr(fmt.Sprintf("serializing current configuration from:\n%v\nfor:", obj), source, err)
	}

	original, err := util.GetOriginalConfiguration(obj)
	if err != nil {
		return nil, nil, cmdutil.AddSourceToErr(fmt.Sprintf("retrieving original configuration from:\n%v\nfor:", obj), source, err)
	}

	var patch []byte
	var lookupPatchMeta strategicpatch.LookupPatchMeta
	var schema oapi.Schema
	createPatchErrFormat := "creating patch with:\noriginal:\n%s\nmodified:\n%s\ncurrent:\n%s\nfor:"

	versionedObject, err := scheme.Scheme.New(p.Mapping.GroupVersionKind)
	switch {
	case runtime.IsNotRegisteredError(err):
		preconditions := []mergepatch.PreconditionFunc{mergepatch.RequireKeyUnchanged("apiVersion"),
			mergepatch.RequireKeyUnchanged("kind"), mergepatch.RequireMetadataKeyUnchanged("name")}
		patch, err = jsonmergepatch.CreateThreeWayJSONMergePatch(original, modified, current, preconditions...)
		if err != nil {
			if mergepatch.IsPreconditionFailed(err) {
				return nil, nil, fmt.Errorf("%s", "At least one of apiVersion, kind and name was changed")
			}
			return nil, nil, cmdutil.AddSourceToErr(fmt.Sprintf(createPatchErrFormat, original, modified, current), source, err)
		}
	case err != nil:
		return nil, nil, cmdutil.AddSourceToErr(fmt.Sprintf("getting instance of versioned object for %v:", p.Mapping.GroupVersionKind), source, err)
	case err == nil:
		if p.OpenapiSchema != nil {
			if schema = p.OpenapiSchema.LookupResource(p.Mapping.GroupVersionKind); schema != nil {
				lookupPatchMeta = strategicpatch.PatchMetaFromOpenAPI{Schema: schema}
				if openapiPatch, err := strategicpatch.CreateThreeWayMergePatch(original, modified, current, lookupPatchMeta, p.Overwrite); err != nil {
					fmt.Fprintf(errOut, "warning: error calculating patch from openapi spec: %v\n", err)
				} else {
					patch = openapiPatch
				}
			}
		}

		if patch == nil {
			lookupPatchMeta, err = strategicpatch.NewPatchMetaFromStruct(versionedObject)
			if err != nil {
				return nil, nil, cmdutil.AddSourceToErr(fmt.Sprintf(createPatchErrFormat, original, modified, current), source, err)
			}
			patch, err = strategicpatch.CreateThreeWayMergePatch(original, modified, current, lookupPatchMeta, p.Overwrite)
			if err != nil {
				return nil, nil, cmdutil.AddSourceToErr(fmt.Sprintf(createPatchErrFormat, original, modified, current), source, err)
			}
		}
	}

	if string(patch) == "{}" {
		return patch, obj, nil
	}

	if p.ResourceVersion != nil {
		patch, err = addResourceVersion(patch, *p.ResourceVersion)
		if err != nil {
			return nil, nil, cmdutil.AddSourceToErr("Failed to insert resourceVersion in patch", source, err)
		}
	}

	creator := scheme.Scheme
	gvk := obj.GetObjectKind().GroupVersionKind()
	mocObj, err := creator.New(gvk)
	if err != nil {
		return nil, nil, fmt.Errorf("Error in getting moc obj; %s", err.Error())
	}
	// patchedObj, err := p.Helper.DryRun(p.ServerDryRun).Patch(namespace, name, patchType, patch, nil)
	patched, err := strategicpatch.StrategicMergePatch(current, patch, mocObj)
	if err != nil {
		return nil, nil, fmt.Errorf("Error in patching to obj; %s", err.Error())
	}
	patchedObj := &unstructured.Unstructured{}
	err = patchedObj.UnmarshalJSON(patched)
	if err != nil {
		return nil, nil, fmt.Errorf("Error in Unmarshal into unstructured obj; %s", err.Error())
	}

	return patch, patchedObj, nil
}

func addResourceVersion(patch []byte, rv string) ([]byte, error) {
	var patchMap map[string]interface{}
	err := json.Unmarshal(patch, &patchMap)
	if err != nil {
		return nil, err
	}
	u := unstructured.Unstructured{Object: patchMap}
	a, err := meta.Accessor(&u)
	if err != nil {
		return nil, err
	}
	a.SetResourceVersion(rv)

	return json.Marshal(patchMap)
}
