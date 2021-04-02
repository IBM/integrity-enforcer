package inspector

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	rspclient "github.com/IBM/integrity-enforcer/shield/pkg/client/resourcesigningprofile/clientset/versioned/typed/resourcesigningprofile/v1alpha1"
	common "github.com/IBM/integrity-enforcer/shield/pkg/common"
	shield "github.com/IBM/integrity-enforcer/shield/pkg/shield"
	sconf "github.com/IBM/integrity-enforcer/shield/pkg/shield/config"
	sconfloader "github.com/IBM/integrity-enforcer/shield/pkg/shield/config/loader"
	kubeutil "github.com/IBM/integrity-enforcer/shield/pkg/util/kubeutil"
	logger "github.com/IBM/integrity-enforcer/shield/pkg/util/logger"
	"github.com/ghodss/yaml"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	admv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	v1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

const defaultResultConfigMapName = "integrity-shield-inspection-result"
const timeFormat = "2006-01-02 15:04:05"

type Inspector struct {
	Config       *sconf.ShieldConfig
	RuleTable    *shield.RuleTable
	APIResources []groupResource

	dynamicClient dynamic.Interface
}

type Result struct {
	Summary     string         `json:"summary"`
	Details     []ResultDetail `json:"details"`
	LastUpdated string         `json:"lastUpdated"`
}

type ResultDetail struct {
	Resource string `json:"resource"`
	Result   string `json:"result"`
	Verified bool   `json:"verified"`
}

// groupResource contains the APIGroup and APIResource
type groupResource struct {
	APIGroup    string             `json:"apiGroup"`
	APIVersion  string             `json:"apiVersion"`
	APIResource metav1.APIResource `json:"resource"`
}

func NewInspector() *Inspector {
	insp := &Inspector{}
	return insp
}

func (self *Inspector) Init() error {
	cfg := sconfloader.NewConfig()
	_ = cfg.InitShieldConfig()
	tmpConfig := cfg.ShieldConfig
	tmpConfig.SideEffect.CreateDenyEvent = false
	tmpConfig.SideEffect.CreateIShieldResourceEvent = false
	tmpConfig.SideEffect.UpdateRSPStatusForDeniedRequest = false
	self.Config = tmpConfig

	kubeconf, _ := kubeutil.GetKubeConfig()

	var err error
	err = self.getRuleTable(self.Config, kubeconf)
	if err != nil {
		return err
	}
	err = self.getAPIResources(kubeconf)
	if err != nil {
		return err
	}

	dynamicClient, err := dynamic.NewForConfig(kubeconf)
	if err != nil {
		return err
	}
	self.dynamicClient = dynamicClient

	return nil
}

func (self *Inspector) Run() {
	// extract GVKs that are defined in any RSPs
	narrowedGVKList := self.narrowDownProtectedAPIResources()

	// get all resources of extracted GVKs
	resources := []unstructured.Unstructured{}
	for _, gResource := range narrowedGVKList {
		tmpResources, _ := self.getAllResoucesByGroupResource(gResource)
		resources = append(resources, tmpResources...)
	}

	// extract resources that are matched with protection rule of RSPs
	protectedResources := []unstructured.Unstructured{}
	for _, res := range resources {
		reqFields := makeDummyReqFields(res)
		if protected, _, _ := self.RuleTable.CheckIfProtected(reqFields); protected {
			protectedResources = append(protectedResources, res)
		}
	}

	// run Integrity Shield handler with dummy admission request
	results := []ResultDetail{}
	for _, resource := range protectedResources {
		gvk := resource.GetObjectKind().GroupVersionKind()
		gvr := convertGVKToGVR(gvk, self.APIResources)

		fmt.Println(resource.GetAPIVersion(), resource.GetKind(), resource.GetNamespace(), resource.GetName())
		metaLogger, reqLog := self.getLoggersForResource(resource)
		handler := shield.NewHandler(self.Config, metaLogger, reqLog)
		dummyRequest := makeDummyAdmissionRequest(resource, gvr)
		resp := handler.Run(dummyRequest)

		resourceInfo := fmt.Sprintf("apiVersion: %s, kind: %s, namespace: %s, name: %s", gvk.GroupVersion().String(), gvk.Kind, resource.GetNamespace(), resource.GetName())
		tmpMsg := strings.Split(resp.Result.Message, " (Request: {")
		resultMsg := ""
		if len(tmpMsg) > 0 {
			resultMsg = tmpMsg[0]
		}
		verified := resp.Allowed
		results = append(results, ResultDetail{
			Resource: resourceInfo,
			Result:   resultMsg,
			Verified: verified,
		})
	}

	self.updateSummary(results)

	return
}

func (self *Inspector) updateSummary(results []ResultDetail) error {

	data := makeResultData(results)

	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		return err
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	cmNS := self.Config.Namespace
	cmName := defaultResultConfigMapName
	cm := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: cmName,
		},
		Data: data,
	}
	alreadyExists := false
	current, getErr := client.CoreV1().ConfigMaps(cmNS).Get(context.Background(), cmName, metav1.GetOptions{})
	if current != nil && getErr == nil {
		alreadyExists = true
		cm = current
		cm.Data = data
	}

	if alreadyExists {
		_, err = client.CoreV1().ConfigMaps(cmNS).Update(context.Background(), cm, metav1.UpdateOptions{})
	} else {
		_, err = client.CoreV1().ConfigMaps(cmNS).Create(context.Background(), cm, metav1.CreateOptions{})
	}
	if err != nil {
		return err
	}
	return nil
}

func (self *Inspector) getRuleTable(sconfig *sconf.ShieldConfig, kubeconfig *rest.Config) error {

	rspClient, _ := rspclient.NewForConfig(kubeconfig)
	tmpRSPList, err := rspClient.ResourceSigningProfiles("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	nsClient, _ := v1client.NewForConfig(kubeconfig)
	tmpNSList, err := nsClient.Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	self.RuleTable = shield.NewRuleTable(tmpRSPList.Items, tmpNSList.Items, sconfig.CommonProfile, sconfig.Namespace)
	return nil
}

func (self *Inspector) getAPIResources(kubeconfig *rest.Config) error {
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

// narrow down API resources scope by checking protectRules & forceCheckRules in RSPs
func (self *Inspector) narrowDownProtectedAPIResources() []groupResource {
	rules := []*common.Rule{}
	for _, ruleItem := range self.RuleTable.Items {
		rules = append(rules, ruleItem.Profile.Spec.ProtectRules...)
		rules = append(rules, ruleItem.Profile.Spec.ForceCheckRules...)
	}

	possibleProtectedGVKs := []groupResource{}
	for _, apiResource := range self.APIResources {
		for _, rule := range rules {
			if checkIfRuleMatchWithGVK(rule, apiResource) {
				possibleProtectedGVKs = append(possibleProtectedGVKs, apiResource)
				break
			}
		}
	}
	return possibleProtectedGVKs
}

func checkIfRuleMatchWithGVK(rule *common.Rule, gvk groupResource) bool {
	if len(rule.Match) == 0 {
		return false
	}
	matched := false
	for _, rp := range rule.Match {
		if rp.ApiGroup == nil && rp.ApiVersion == nil && rp.Kind == nil {
			continue
		}
		patternCount := 0
		matchedCount := 0
		if rp.ApiGroup != nil {
			patternCount++
			if common.MatchPattern(string(*(rp.ApiGroup)), gvk.APIGroup) {
				matchedCount++
			}
		}
		if rp.ApiVersion != nil {
			patternCount++
			if common.MatchPattern(string(*(rp.ApiVersion)), gvk.APIVersion) {
				matchedCount++
			}
		}
		if rp.Kind != nil {
			patternCount++
			if common.MatchPattern(string(*(rp.Kind)), gvk.APIResource.Kind) {
				matchedCount++
			}
		}
		if patternCount == matchedCount {
			matched = true
			break
		}
	}
	return matched
}

func (self *Inspector) getAllResoucesByGroupResource(gResource groupResource) ([]unstructured.Unstructured, error) {
	var resources *unstructured.UnstructuredList
	var err error
	namespaced := gResource.APIResource.Namespaced
	gvr := schema.GroupVersionResource{
		Group:    gResource.APIGroup,
		Version:  gResource.APIVersion,
		Resource: gResource.APIResource.Name,
	}
	if namespaced {
		resources, err = self.dynamicClient.Resource(gvr).Namespace("").List(context.Background(), metav1.ListOptions{})
	} else {
		resources, err = self.dynamicClient.Resource(gvr).List(context.Background(), metav1.ListOptions{})
	}
	if err != nil {
		// ignore RBAC error - IShield SA
		fmt.Println("RBAC error when listing resources; error:", err.Error())
		return []unstructured.Unstructured{}, nil
	}
	return resources.Items, nil
}

func (self *Inspector) getLoggersForResource(resource unstructured.Unstructured) (*log.Logger, *log.Entry) {
	gvk := resource.GetObjectKind()
	gv := metav1.GroupVersion{Group: gvk.GroupVersionKind().Group, Version: gvk.GroupVersionKind().Version}
	metaLogger := logger.NewLogger(self.Config.LoggerConfig())
	reqLog := metaLogger.WithFields(
		log.Fields{
			"namespace":  resource.GetNamespace(),
			"name":       resource.GetName(),
			"apiVersion": gv.String(),
			"kind":       gvk.GroupVersionKind().Kind,
			"operation":  "CREATE",
			"requestUID": uuid.NewString(),
		},
	)
	return metaLogger, reqLog
}

func convertGVKToGVR(gvk schema.GroupVersionKind, apiResouces []groupResource) schema.GroupVersionResource {
	found := schema.GroupVersionResource{}
	for _, gResource := range apiResouces {
		groupOk := (gResource.APIGroup == gvk.Group)
		versionOK := (gResource.APIVersion == gvk.Version)
		kindOk := (gResource.APIResource.Kind == gvk.Kind)
		if groupOk && versionOK && kindOk {
			found = schema.GroupVersionResource{
				Group:    gvk.Group,
				Version:  gvk.Version,
				Resource: gResource.APIResource.Name,
			}
			break
		}
	}
	return found
}

func makeDummyReqFields(resource unstructured.Unstructured) map[string]string {

	objKind := resource.GetObjectKind()
	apiGroup := objKind.GroupVersionKind().Group
	apiVersion := objKind.GroupVersionKind().Version
	kind := resource.GetKind()
	namespace := resource.GetNamespace()
	name := resource.GetName()
	resourceScope := "Namespaced"
	if namespace == "" {
		resourceScope = "Cluster"
	}
	reqFields := map[string]string{
		"ApiGroup":      apiGroup,
		"ApiVersion":    apiVersion,
		"Kind":          kind,
		"Namespace":     namespace,
		"Name":          name,
		"ResourceScope": resourceScope,
	}
	return reqFields
}

func makeDummyAdmissionRequest(resource unstructured.Unstructured, gvr schema.GroupVersionResource) *admv1.AdmissionRequest {
	objKind := resource.GetObjectKind().GroupVersionKind()
	namespace := resource.GetNamespace()
	name := resource.GetName()
	uid := types.UID(uuid.NewString())
	mgvk := metav1.GroupVersionKind{
		Group:   objKind.Group,
		Version: objKind.Version,
		Kind:    objKind.Kind,
	}
	mgvr := metav1.GroupVersionResource{
		Group:    objKind.Group,
		Version:  objKind.Version,
		Resource: gvr.Resource,
	}

	resBytes, _ := json.Marshal(resource.Object)
	dryRun := false
	return &admv1.AdmissionRequest{
		UID:       uid,
		Kind:      mgvk,
		Resource:  mgvr,
		Namespace: namespace,
		Name:      name,
		Operation: admv1.Create,
		Object: runtime.RawExtension{
			Raw:    resBytes,
			Object: &resource,
		},
		UserInfo: authenticationv1.UserInfo{
			Username: "system:serviceaccount:dummy-ns:dummy-user",
			Groups:   []string{"system:dummy-group"},
		},
		DryRun: &dryRun,
	}
}

func makeResultData(results []ResultDetail) map[string]string {
	totalNum := len(results)
	verifiedCount := 0
	for _, r := range results {
		if r.Verified {
			verifiedCount++
		}
	}
	summary := fmt.Sprintf("verified: %v / %v", verifiedCount, totalNum)
	lastUpdated := time.Now().UTC().Format(timeFormat)

	res := Result{
		Summary:     summary,
		Details:     results,
		LastUpdated: lastUpdated,
	}
	resultStr, _ := yaml.Marshal(res)
	data := map[string]string{
		"result.yaml": string(resultStr),
	}
	return data
}
