package inspector

import (
	"context"
	"encoding/json"
	"fmt"

	rspclient "github.com/IBM/integrity-enforcer/shield/pkg/client/resourcesigningprofile/clientset/versioned/typed/resourcesigningprofile/v1alpha1"
	shield "github.com/IBM/integrity-enforcer/shield/pkg/shield"
	sconf "github.com/IBM/integrity-enforcer/shield/pkg/shield/config"
	sconfloader "github.com/IBM/integrity-enforcer/shield/pkg/shield/config/loader"
	kubeutil "github.com/IBM/integrity-enforcer/shield/pkg/util/kubeutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	v1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

type Inspector struct {
	Config       *sconf.ShieldConfig
	RuleTable    *shield.RuleTable
	APIResources []groupResource
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
	self.Config = cfg.ShieldConfig

	kubeconf, _ := kubeutil.GetKubeConfig()
	rspClient, _ := rspclient.NewForConfig(kubeconf)
	tmpRSPList, err := rspClient.ResourceSigningProfiles("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	nsClient, _ := v1client.NewForConfig(kubeconf)
	tmpNSList, err := nsClient.Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	self.RuleTable = shield.NewRuleTable(tmpRSPList.Items, tmpNSList.Items, self.Config.CommonProfile, self.Config.Namespace)

	discoveryClient, err := discovery.NewDiscoveryClientForConfig(kubeconf)
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

func (self *Inspector) Run() {
	resourceBytes, _ := json.Marshal(self.APIResources)
	fmt.Println("[DEBUG] resources: ", string(resourceBytes))
	return
}
