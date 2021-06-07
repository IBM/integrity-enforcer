package util

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	"github.com/ghodss/yaml"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const defaultArgoCDNamespace = "argocd"

const argocdNamespaceEnv = "ARGOCD_NAMESPACE"

var argoCDNamespace string

func GetArgoCDNamespace() string {
	argoCDNamespace = os.Getenv(argocdNamespaceEnv)
	if argoCDNamespace != "" {
		return argoCDNamespace
	}
	return defaultArgoCDNamespace
}

func SetArgoCDNamespace(n string) {
	argoCDNamespace = n
}

func ReadApplicationYAMLFile(appFileName string) (*v1alpha1.Application, error) {
	namespace := GetArgoCDNamespace()
	data, err := ioutil.ReadFile(appFileName)
	if err != nil {
		fmt.Println("[DEBUG] failed to read ", appFileName, " ; ", err)
		return nil, err
	}
	var app *v1alpha1.Application
	err = yaml.Unmarshal(data, &app)
	if err != nil {
		fmt.Println("[DEBUG] failed to Unmarshal into Application; ", err)
		return nil, err
	}
	appNS := app.GetNamespace()
	if appNS == "" {
		app.SetNamespace(namespace)
	}
	return app, nil
}

func ReadAppProjectYAMLFile(appprojFileName string) (*v1alpha1.AppProject, error) {
	namespace := GetArgoCDNamespace()
	data, err := ioutil.ReadFile(appprojFileName)
	if err != nil {
		fmt.Println("[DEBUG] failed to read ", appprojFileName, " ; ", err)
		return nil, err
	}
	var appproj *v1alpha1.AppProject
	err = yaml.Unmarshal(data, &appproj)
	if err != nil {
		fmt.Println("[DEBUG] failed to Unmarshal into Application; ", err)
		return nil, err
	}
	apjNS := appproj.GetNamespace()
	if apjNS == "" {
		appproj.SetNamespace(namespace)
	}
	return appproj, nil
}

func ReadPluginCMYAMLFile(cmFileName string) (*corev1.ConfigMap, error) {
	namespace := GetArgoCDNamespace()
	data, err := ioutil.ReadFile(cmFileName)
	if err != nil {
		fmt.Println("[DEBUG] failed to read ", cmFileName, " ; ", err)
		return nil, err
	}
	var cm *corev1.ConfigMap
	err = yaml.Unmarshal(data, &cm)
	if err != nil {
		fmt.Println("[DEBUG] failed to Unmarshal into Application; ", err)
		return nil, err
	}
	cmNS := cm.GetNamespace()
	if cmNS == "" {
		cm.SetNamespace(namespace)
	}
	return cm, nil
}

func LoadAllResources(yamlDir string) ([]*unstructured.Unstructured, error) {
	files, err := ioutil.ReadDir(yamlDir)
	if err != nil {
		return nil, err
	}
	resources := []*unstructured.Unstructured{}
	sumErr := []string{}
	for _, f := range files {
		if !f.IsDir() && (path.Ext(f.Name()) == ".yaml" || path.Ext(f.Name()) == ".yml") {
			fpath := filepath.Join(yamlDir, f.Name())
			data, err := ioutil.ReadFile(fpath)
			if err != nil {
				sumErr = append(sumErr, err.Error())
				continue
			}
			var obj *unstructured.Unstructured
			err = yaml.Unmarshal(data, &obj)
			if err != nil {
				sumErr = append(sumErr, err.Error())
				continue
			}
			resources = append(resources, obj)
		}
	}
	if len(resources) == 0 && len(sumErr) > 0 {
		return nil, fmt.Errorf(strings.Join(sumErr, "; "))
	}
	return resources, nil
}
