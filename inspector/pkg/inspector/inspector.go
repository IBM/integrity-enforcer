package inspector

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	priapi "github.com/IBM/integrity-enforcer/inspector/pkg/apis/protectedresourceintegrity/v1alpha1"
	priclient "github.com/IBM/integrity-enforcer/inspector/pkg/client/protectedresourceintegrity/clientset/versioned/typed/protectedresourceintegrity/v1alpha1"
	rspapi "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesigningprofile/v1alpha1"
	rspclient "github.com/IBM/integrity-enforcer/shield/pkg/client/resourcesigningprofile/clientset/versioned/typed/resourcesigningprofile/v1alpha1"
	common "github.com/IBM/integrity-enforcer/shield/pkg/common"
	shield "github.com/IBM/integrity-enforcer/shield/pkg/shield"
	sconf "github.com/IBM/integrity-enforcer/shield/pkg/shield/config"
	sconfloader "github.com/IBM/integrity-enforcer/shield/pkg/shield/config/loader"
	kubeutil "github.com/IBM/integrity-enforcer/shield/pkg/util/kubeutil"
	logger "github.com/IBM/integrity-enforcer/shield/pkg/util/logger"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	admv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	v1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

const timeFormat = "2006-01-02 15:04:05"

type Inspector struct {
	Config       *sconf.ShieldConfig
	RuleTable    *shield.RuleTable
	APIResources []groupResource

	dynamicClient dynamic.Interface
}

type NamespacedRule struct {
	Rule             *common.Rule
	TargetNamespaces []string
}

type Result struct {
	Summary     string         `json:"summary"`
	Details     []ResultDetail `json:"details"`
	LastUpdated string         `json:"lastUpdated"`
}

type ResultDetail struct {
	Resource ProtectedResource `json:"resource"`
	Result   string            `json:"result"`
	Verified bool              `json:"verified"`
}

type ProtectedResource struct {
	unstructured.Unstructured
	Profiles []rspapi.ResourceSigningProfile
}

type groupResourceWithTargetNS struct {
	groupResource
	TargetNamespaces []string
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
	protectedResources := []ProtectedResource{}
	for _, res := range resources {
		reqFields := makeDummyReqFields(res)
		if protected, _, profiles := self.RuleTable.CheckIfProtected(reqFields); protected {
			protectedResources = append(protectedResources, ProtectedResource{Unstructured: res, Profiles: profiles})
		}
	}

	// run Integrity Shield handler with dummy admission request
	results := []ResultDetail{}
	for _, resource := range protectedResources {
		gvk := resource.GetObjectKind().GroupVersionKind()
		gvr := convertGVKToGVR(gvk, self.APIResources)

		fmt.Println(resource.GetAPIVersion(), resource.GetKind(), resource.GetNamespace(), resource.GetName())
		metaLogger, reqLog := self.getLoggersForResource(resource.Unstructured)
		handler := shield.NewHandler(self.Config, metaLogger, reqLog)
		dummyRequest := makeDummyAdmissionRequest(resource.Unstructured, gvr)
		resp := handler.Run(dummyRequest)

		tmpMsg := strings.Split(resp.Result.Message, " (Request: {")
		resultMsg := ""
		if len(tmpMsg) > 0 {
			resultMsg = tmpMsg[0]
		}
		verified := resp.Allowed
		results = append(results, ResultDetail{
			Resource: resource,
			Result:   resultMsg,
			Verified: verified,
		})
	}

	self.updateSummary(results)

	return
}

func (self *Inspector) updateSummary(results []ResultDetail) error {

	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		return err
	}
	client, err := priclient.NewForConfig(config)
	if err != nil {
		return err
	}

	ishieldNS := self.Config.Namespace

	for _, result := range results {
		gvk := result.Resource.GetObjectKind().GroupVersionKind()
		profiles := result.Resource.Profiles
		profilesStr := ""
		for i, prof := range profiles {
			profNS := prof.GetNamespace()
			profName := prof.GetName()
			profilesStr = profilesStr + profNS + "/" + profName
			if i != len(profiles)-1 {
				profilesStr = profilesStr + ","
			}
		}

		resAPIVersion := gvk.GroupVersion().String()
		resKind := gvk.Kind
		resNamespace := result.Resource.GetNamespace()
		resName := result.Resource.GetName()

		verified := result.Verified
		result := result.Result
		var lastVerified, lastUpdated metav1.Time
		if verified {
			lastVerified = metav1.NewTime(time.Now().UTC())
		}
		lastUpdated = metav1.NewTime(time.Now().UTC())
		allowedUsernames := ""

		nsPrefix := ""
		if resNamespace != "" {
			nsPrefix = resNamespace + "-"
		}
		priName := fmt.Sprintf("%s%s-%s", nsPrefix, strings.ToLower(resKind), resName)
		priInstance := &priapi.ProtectedResourceIntegrity{
			ObjectMeta: metav1.ObjectMeta{
				Name: priName,
			},
			Spec: priapi.ProtectedResourceIntegritySpec{
				APIVersion: resAPIVersion,
				Kind:       resKind,
				Namespace:  resNamespace,
				Name:       resName,
			},
			Status: priapi.ProtectedResourceIntegrityStatus{
				Verified:         verified,
				Result:           result,
				LastVerified:     lastVerified,
				LastUpdated:      lastUpdated,
				Profiles:         profilesStr,
				AllowedUsernames: allowedUsernames,
			},
		}
		alreadyExists := false
		current, getErr := client.ProtectedResourceIntegrities(ishieldNS).Get(context.Background(), priName, metav1.GetOptions{})
		if current != nil && getErr == nil {
			alreadyExists = true
			if !verified {
				priInstance.Status.LastVerified = current.Status.LastVerified
			}
			current.Status = priInstance.Status
		}

		if alreadyExists {
			_, err = client.ProtectedResourceIntegrities(ishieldNS).Update(context.Background(), current, metav1.UpdateOptions{})
		} else {
			_, err = client.ProtectedResourceIntegrities(ishieldNS).Create(context.Background(), priInstance, metav1.CreateOptions{})
		}
		if err != nil {
			return err
		}
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
func (self *Inspector) narrowDownProtectedAPIResources() []groupResourceWithTargetNS {
	rules := []NamespacedRule{}
	for _, ruleItem := range self.RuleTable.Items {
		for _, rule := range ruleItem.Profile.Spec.ProtectRules {
			rules = append(rules, NamespacedRule{Rule: rule, TargetNamespaces: ruleItem.TargetNamespaces})
		}
		for _, rule := range ruleItem.Profile.Spec.ForceCheckRules {
			rules = append(rules, NamespacedRule{Rule: rule, TargetNamespaces: ruleItem.TargetNamespaces})
		}
	}

	possibleProtectedGVKs := []groupResourceWithTargetNS{}
	for _, apiResource := range self.APIResources {
		for _, rule := range rules {
			if checkIfRuleMatchWithGVK(rule.Rule, apiResource) {
				tmp := groupResourceWithTargetNS{groupResource: apiResource, TargetNamespaces: rule.TargetNamespaces}
				possibleProtectedGVKs = append(possibleProtectedGVKs, tmp)
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

func (self *Inspector) getAllResoucesByGroupResource(gResourceWithTargetNS groupResourceWithTargetNS) ([]unstructured.Unstructured, error) {
	var resources []unstructured.Unstructured
	var err error
	var gResource groupResource
	gResource = gResourceWithTargetNS.groupResource
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
		fmt.Println("RBAC error when listing resources; error:", err.Error())
		return []unstructured.Unstructured{}, nil
	}
	return resources, nil
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
