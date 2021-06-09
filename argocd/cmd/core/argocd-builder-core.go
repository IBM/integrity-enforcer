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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	argocontroller "github.com/argoproj/argo-cd/v2/controller"
	"github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/IBM/integrity-enforcer/argocd/pkg/util"
	"github.com/argoproj/argo-cd/v2/reposerver/metrics"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

const configManagementPluginsKey = "configManagementPlugins"

var debugMode bool
var config *rest.Config

const inContainerAppConfigPath = "/tmp/appconfig"

type argoCDConfiguration struct {
	namespace             string
	argocdCm              *corev1.ConfigMap
	argocdSecret          *corev1.Secret
	argocdRbacCm          *corev1.ConfigMap
	argocdTlsCertsCm      *corev1.ConfigMap
	argocdSshKnownHostsCm *corev1.ConfigMap
}

func (c *argoCDConfiguration) createConfigs() error {
	ctx := context.Background()
	kubeclientset := kubernetes.NewForConfigOrDie(config)

	argoNS := c.namespace
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: argoNS,
		},
	}
	var err error
	_, err = kubeclientset.CoreV1().Namespaces().Create(ctx, namespace, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	_, err = kubeclientset.CoreV1().ConfigMaps(argoNS).Create(ctx, c.argocdCm, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	return nil
}

func init() {

	testEnv := &envtest.Environment{}

	var err error
	config, err = testEnv.Start()
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to start testenv", err)
		os.Exit(1)
	}
}

func getManifestObjectsFromApplication(a *v1alpha1.Application, p *v1alpha1.AppProject, c *argoCDConfiguration) ([]*unstructured.Unstructured, error) {

	err := c.createConfigs()
	if err != nil {
		return nil, fmt.Errorf("[DEBUG] create config err; %s", err.Error())
	}

	namespace := c.namespace
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

	permittedHelmRepos, err := argo.GetPermittedRepos(p, helmRepos)
	if err != nil {
		return nil, fmt.Errorf("[DEBUG] get permittedHelmRepos err; %s", err.Error())
	}

	plugins, err := getPluginsFromCM(c.argocdCm)
	if err != nil {
		return nil, fmt.Errorf("[DEBUG] get plugins err; %s", err.Error())
	}

	kubectl := kubeutil.NewKubectl()
	serverVersion, err := kubectl.GetServerVersion(config)
	if err != nil {
		return nil, fmt.Errorf("[DEBUG] get serverVersion err; %s", err.Error())
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

func getPluginsFromCM(cm *corev1.ConfigMap) ([]*v1alpha1.ConfigManagementPlugin, error) {
	pluginDataBytes, ok := cm.Data[configManagementPluginsKey]
	if !ok {
		// accept no data in the CM
		return []*v1alpha1.ConfigManagementPlugin{}, nil
	}
	var plugins []v1alpha1.ConfigManagementPlugin
	err := yaml.Unmarshal([]byte(pluginDataBytes), &plugins)
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

func NewArgocdBuilderCoreCommand() *cobra.Command {
	var debug bool
	cmd := &cobra.Command{
		Use:   "argocd-builder-core",
		Short: "A command to generate YAMLs from ArgoCD Application definition",
		RunE: func(cmd *cobra.Command, args []string) error {
			if debug {
				debugMode = true
			}
			manifest, err := generateYAMLs()
			if err != nil {
				return err
			}
			fmt.Println(manifest)
			return nil
		},
	}

	cmd.PersistentFlags().BoolVar(&debug, "debug", false, "debug mode")

	return cmd
}

func main() {

	cmd := NewArgocdBuilderCoreCommand()
	cmd.SetOutput(os.Stdout)
	if err := cmd.Execute(); err != nil {
		cmd.SetOutput(os.Stderr)
		cmd.Println(err)
		os.Exit(1)
	}
	os.Exit(0)
}

func base64Decode(in string) string {
	out, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		return in
	}
	return string(out)
}

func generateYAMLs() (string, error) {

	inputObjs, err := util.LoadAllResources(inContainerAppConfigPath)
	if err != nil {
		return "", errors.Wrap(err, "[DEBUG] failed to load input YAMLs;")
	}

	var app *v1alpha1.Application
	var proj *v1alpha1.AppProject
	var argocdCM *corev1.ConfigMap
	for _, obj := range inputObjs {
		kind := obj.GetKind()
		name := obj.GetName()
		if kind == "Application" {
			objB, _ := json.Marshal(obj)
			_ = json.Unmarshal(objB, &app)
		} else if kind == "AppProject" {
			objB, _ := json.Marshal(obj)
			_ = json.Unmarshal(objB, &proj)
		} else if kind == "ConfigMap" && name == "argocd-cm" {
			objB, _ := json.Marshal(obj)
			_ = json.Unmarshal(objB, &argocdCM)
		}
	}
	if app == nil {
		return "", errors.New("[DEBUG] failed to load Application from input directory")
	}
	if proj == nil {
		return "", errors.New("[DEBUG] failed to load AppProject from input directory")
	}
	if argocdCM == nil {
		return "", errors.New("[DEBUG] failed to load `argocd-cm` ConfigMap from input directory")
	}

	var objs []*unstructured.Unstructured

	argoConfig := &argoCDConfiguration{
		namespace: argocdCM.GetNamespace(),
		argocdCm:  argocdCM,
	}

	// ArgoCD functions prints various logs in stdout, so use silentCallFunc() to discard them
	retVal, internalLogs := silentCallFunc(getManifestObjectsFromApplication, app, proj, argoConfig)
	if debugMode {
		fmt.Println("[DEUBG] internalLogs:", internalLogs)
	}
	if len(retVal) != 2 {
		return "", errors.Wrap(err, "[DEBUG] unexpected returned value from getManifestObjectsFromApplication()")
	}
	if retVal[0] != nil {
		objs = retVal[0].([]*unstructured.Unstructured)
	}
	if retVal[1] != nil {
		err = retVal[1].(error)
	}
	if err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("[DEBUG] getManifestObjectsFromApplication err; internal err logs: %s", internalLogs))
	}

	manifest, err := generateManifestFromObjects(objs)
	if err != nil {
		return "", errors.Wrap(err, "[DEBUG] generateManifestFromObjects err")
	}
	return string(manifest), nil
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
