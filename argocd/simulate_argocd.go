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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"time"

	argocontroller "github.com/argoproj/argo-cd/v2/controller"
	"github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	appclientset "github.com/argoproj/argo-cd/v2/pkg/client/clientset/versioned"
	"github.com/argoproj/argo-cd/v2/reposerver/apiclient"
	reposervercache "github.com/argoproj/argo-cd/v2/reposerver/cache"
	"github.com/argoproj/argo-cd/v2/reposerver/repository"
	"github.com/argoproj/argo-cd/v2/util/argo"
	cacheutil "github.com/argoproj/argo-cd/v2/util/cache"
	dbutil "github.com/argoproj/argo-cd/v2/util/db"
	kubeutil "github.com/argoproj/argo-cd/v2/util/kube"
	settingsutil "github.com/argoproj/argo-cd/v2/util/settings"
	"github.com/ghodss/yaml"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	apierr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/argoproj/argo-cd/v2/reposerver/metrics"
)

const defaultArgoCDNamespace = "argocd"

var argoCDNamespace string
var config *rest.Config
var clientConfig clientcmd.ClientConfig

func init() {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	overrides := clientcmd.ConfigOverrides{}
	clientConfig = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &overrides)
	var err error
	config, err = clientConfig.ClientConfig()
	if err != nil {
		fmt.Println("[DEBUG] get config err; ", err)
		return
	}
}

func GetArgoCDNamespace() string {
	if argoCDNamespace != "" {
		return argoCDNamespace
	}
	return defaultArgoCDNamespace
}

func SetArgoCDNamespace(n string) {
	argoCDNamespace = n
}

func getApplicationByAppName(appName string) (*v1alpha1.Application, error) {
	namespace := GetArgoCDNamespace()
	appClient, err := appclientset.NewForConfig(config)
	if err != nil {
		fmt.Println("[DEBUG] create application client err; ", err)
		return nil, err
	}
	app, err := appClient.ArgoprojV1alpha1().Applications(namespace).Get(context.Background(), appName, metav1.GetOptions{})
	if err != nil {
		fmt.Println("[DEBUG] get application err; ", err)
		return nil, err
	}
	return app, nil
}

func getAppProjectByAppName(apjName string) (*v1alpha1.AppProject, error) {
	namespace := GetArgoCDNamespace()
	appClient, err := appclientset.NewForConfig(config)
	if err != nil {
		fmt.Println("[DEBUG] create application client err; ", err)
		return nil, err
	}
	apj, err := appClient.ArgoprojV1alpha1().AppProjects(namespace).Get(context.Background(), apjName, metav1.GetOptions{})
	if err != nil {
		fmt.Println("[DEBUG] get application err; ", err)
		return nil, err
	}
	return apj, nil
}

func getManifestObjectsFromApplication(a *v1alpha1.Application) ([]*unstructured.Unstructured, error) {

	namespace := GetArgoCDNamespace()
	kubeclientset := kubernetes.NewForConfigOrDie(config)
	settingsMgr := settingsutil.NewSettingsManager(context.Background(), kubeclientset, namespace)

	metricsServer := metrics.NewMetricsServer()
	inMemoryCache := cacheutil.NewInMemoryCache(1 * time.Minute)
	cacheInst := cacheutil.NewCache(inMemoryCache)
	cache := reposervercache.NewCache(cacheInst, 24*time.Hour, 10*time.Minute)

	repoService := repository.NewService(metricsServer, cache, repository.RepoServerInitConstants{})

	db := dbutil.NewDB(namespace, settingsMgr, kubeclientset)
	repo, err := db.GetRepository(context.Background(), a.Spec.Source.RepoURL)
	if err != nil {
		return nil, fmt.Errorf("[DEBUG] get repository err; %s", err.Error())
	}
	appInstanceLabelKey, err := settingsMgr.GetAppInstanceLabelKey()
	if err != nil {
		return nil, fmt.Errorf("[DEBUG] get appInstanceLabelKey err; %s", err.Error())
	}
	helmRepos, err := db.ListHelmRepositories(context.Background())
	if err != nil {
		return nil, fmt.Errorf("[DEBUG] list HelmRepositories err; %s", err.Error())
	}

	proj, err := getAppProjectByAppName(a.Spec.Project)
	if err != nil {
		if apierr.IsNotFound(err) {
			err := status.Errorf(codes.InvalidArgument, "application references project %s which does not exist", a.Spec.Project)
			return nil, fmt.Errorf("[DEBUG] get AppProject err; %s", err.Error())
		} else {
			return nil, fmt.Errorf("[DEBUG] get AppProject err; %s", err.Error())
		}
	}

	permittedHelmRepos, err := argo.GetPermittedRepos(proj, helmRepos)
	if err != nil {
		return nil, fmt.Errorf("[DEBUG] get permittedHelmRepos err; %s", err.Error())
	}

	plugins, err := getPlugins(settingsMgr)
	if err != nil {
		return nil, fmt.Errorf("[DEBUG] get plugins err; %s", err.Error())
	}

	kubectl := kubeutil.NewKubectl()
	serverVersion, err := kubectl.GetServerVersion(config)
	if err != nil {
		return nil, fmt.Errorf("[DEBUG] get serverVersion err; %s", err.Error())
	}

	apiGroups, err := kubectl.GetAPIGroups(config)
	if err != nil {
		return nil, fmt.Errorf("[DEBUG] get apiGroups err; %s", err.Error())
	}

	kustomizeSettings, err := settingsMgr.GetKustomizeSettings()
	if err != nil {
		return nil, fmt.Errorf("[DEBUG] get kustomizeSettings err; %s", err.Error())
	}
	kustomizeOptions, err := kustomizeSettings.GetOptions(a.Spec.Source)
	if err != nil {
		return nil, fmt.Errorf("[DEBUG] get kustomizeOptions err; %s", err.Error())
	}

	// helmRepositoryCredentials, err := db.GetAllHelmRepositoryCredentials(context.Background())
	// if err != nil {
	// 	fmt.Println("[DEBUG] get helmRepositoryCredentials err; ", err)
	// }
	// permittedHelmCredentials, err := argo.GetPermittedReposCredentials(proj, helmRepositoryCredentials)
	// if err != nil {
	// 	fmt.Println("[DEBUG] get permittedHelmCredentials err; ", err)
	// }

	manifestRequest := &apiclient.ManifestRequest{
		Repo:              repo,
		Revision:          a.Spec.Source.TargetRevision,
		AppLabelKey:       appInstanceLabelKey,
		AppName:           a.Name,
		Namespace:         a.Spec.Destination.Namespace,
		ApplicationSource: &a.Spec.Source,
		Repos:             permittedHelmRepos,
		Plugins:           plugins,
		KustomizeOptions:  kustomizeOptions,
		KubeVersion:       serverVersion,
		ApiVersions:       argo.APIGroupsToVersions(apiGroups),
		// HelmRepoCreds:     permittedHelmCredentials,
	}

	manifestInfo, err := repoService.GenerateManifest(context.Background(), manifestRequest)
	if err != nil {
		return nil, fmt.Errorf("[DEBUG] generate manifest err; %s", err.Error())
	}
	objects := []*unstructured.Unstructured{}
	for _, manifest := range manifestInfo.Manifests {
		var obj *unstructured.Unstructured
		err := json.Unmarshal([]byte(manifest), &obj)
		if err != nil {
			return nil, fmt.Errorf("[DEBUG] JSONToYAML err; %s", err.Error())
		} else if obj != nil {
			objects = append(objects, obj)
		}
	}
	namespacedByGk, err := getNamaspacedByGk()
	if err != nil {
		return nil, fmt.Errorf("[DEBUG] getNamaspacedByGk err; %s", err.Error())
	}
	infoProvider := &resourceInfoProvider{namespacedByGk: namespacedByGk}
	cleanObjects, _, err := argocontroller.DeduplicateTargetObjects(a.Spec.Destination.Namespace, objects, infoProvider)
	if err != nil {
		return nil, fmt.Errorf("[DEBUG] deduplicate & set namespace err; %s", err.Error())
	}
	return cleanObjects, err

}

func getPlugins(settingsMgr *settingsutil.SettingsManager) ([]*v1alpha1.ConfigManagementPlugin, error) {
	plugins, err := settingsMgr.GetConfigManagementPlugins()
	if err != nil {
		return nil, err
	}
	tools := make([]*v1alpha1.ConfigManagementPlugin, len(plugins))
	for i, p := range plugins {
		p := p
		tools[i] = &p
	}
	return tools, nil
}

func generateManifestFromObjects(objs []*unstructured.Unstructured) ([]byte, error) {
	result := ""
	sumErr := []string{}
	var retErr error
	for i, obj := range objs {
		objBytes, err := yaml.Marshal(obj)
		if err != nil {
			sumErr = append(sumErr, err.Error())
			continue
		}
		endLine := ""
		if !strings.HasSuffix(string(objBytes), "\n") {
			endLine = "\n"
		}
		result = fmt.Sprintf("%s%s%s", result, string(objBytes), endLine)
		if i < len(objs)-1 {
			result = fmt.Sprintf("%s---\n", result)
		}
	}
	if len(sumErr) > 0 {
		tmp := strings.Join(sumErr, "; ")
		retErr = fmt.Errorf("error occured while generating output. errors: %s", tmp)
	}
	return []byte(result), retErr
}

func silentCallFunc(f interface{}, i ...interface{}) ([]interface{}, string) {
	// if f is not a function, exit this
	if reflect.ValueOf(f).Type().Kind() != reflect.Func {
		return nil, ""
	}

	// create virtual output
	rStdout, wStdout, _ := os.Pipe()
	rStderr, wStderr, _ := os.Pipe()
	channel := make(chan string)

	// backup all output
	backupStdout := os.Stdout
	backupStderr := os.Stderr
	backupLoggerOut := log.StandardLogger().Out

	// overwrite output configuration with virtual output
	os.Stdout = wStdout
	os.Stderr = wStderr
	log.SetOutput(wStdout)

	// set a channel as a stdout buffer
	go func(out chan string, readerStdout *os.File, readerStderr *os.File) {
		var bufStdout bytes.Buffer
		_, _ = io.Copy(&bufStdout, readerStdout)
		if bufStdout.Len() > 0 {
			out <- bufStdout.String()
		}

		var bufStderr bytes.Buffer
		_, _ = io.Copy(&bufStderr, readerStderr)
		if bufStderr.Len() > 0 {
			out <- bufStderr.String()
		}
	}(channel, rStdout, rStderr)

	// configure channel so that all recevied string would be inserted into vStdout
	vStdout := ""
	go func() {
		for {
			select {
			case out := <-channel:
				vStdout += out
			}
		}
	}()

	// call the function
	in := []reflect.Value{}
	for _, ii := range i {
		in = append(in, reflect.ValueOf(ii))
	}
	o := []interface{}{}
	out := reflect.ValueOf(f).Call(in)
	for _, oi := range out {
		o = append(o, oi.Interface())
	}

	// close vitual output
	_ = wStdout.Close()
	_ = wStderr.Close()
	time.Sleep(10 * time.Millisecond)

	// restore original output configuration
	os.Stdout = backupStdout
	os.Stderr = backupStderr
	log.SetOutput(backupLoggerOut)
	return o, vStdout
}

func main() {
	appName := ""
	if len(os.Args) > 0 {
		appName = os.Args[1]
	}
	app, err := getApplicationByAppName(appName)
	if err != nil {
		fmt.Println("[DEBUG] getApplicationByAppName err", err)
		return
	}

	var objs []*unstructured.Unstructured

	// ArgoCD functions prints various logs in stdout, so use silentCallFunc() to discard them
	retVal, internalLogs := silentCallFunc(getManifestObjectsFromApplication, app)
	if len(retVal) != 2 {
		fmt.Println("[DEBUG] unexpected returned value from getManifestObjectsFromApplication()")
		return
	}
	if retVal[0] != nil {
		objs = retVal[0].([]*unstructured.Unstructured)
	}
	if retVal[1] != nil {
		err = retVal[1].(error)
	}
	if err != nil {
		fmt.Println("internal logs: ", internalLogs)
		fmt.Println("[DEBUG] getManifestObjectsFromApplication err", err)
		return
	}

	manifest, err := generateManifestFromObjects(objs)
	if err != nil {
		fmt.Println("[DEBUG] generateManifestFromObjects err", err)
		return
	}
	fmt.Println(string(manifest))

}

func getAPIResources() ([]metav1.APIResource, error) {
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return nil, err
	}

	apiResourceLists, err := discoveryClient.ServerPreferredResources()
	if err != nil {
		return nil, err
	}

	resources := []metav1.APIResource{}
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
			gvResource := resource
			gvResource.Group = gv.Group
			gvResource.Version = gv.Version
			resources = append(resources, gvResource)
		}
	}
	return resources, nil
}

func getNamaspacedByGk() (map[schema.GroupKind]bool, error) {
	m := map[schema.GroupKind]bool{}
	apiResources, err := getAPIResources()
	if err != nil {
		return nil, err
	}
	for _, r := range apiResources {
		gk := schema.GroupKind{Group: r.Group, Kind: r.Kind}
		namespaced := r.Namespaced
		m[gk] = namespaced
	}
	return m, nil
}

type resourceInfoProvider struct {
	namespacedByGk map[schema.GroupKind]bool
}

func (p *resourceInfoProvider) IsNamespaced(gk schema.GroupKind) (bool, error) {
	return p.namespacedByGk[gk], nil
}
