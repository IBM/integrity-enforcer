package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	_ "embed" // To enable the `go:embed` directive.

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	rareviewv1alpha1 "github.com/IBM/integrity-enforcer/controller/pkg/apis/resourceauditreview/v1alpha1"
	clientset "github.com/IBM/integrity-enforcer/controller/pkg/client/resourceauditreview/clientset/versioned"
	sconfloder "github.com/IBM/integrity-enforcer/shield/pkg/config/loader"
	"github.com/IBM/integrity-enforcer/shield/pkg/util/kubeutil"
)

var config *sconfloder.Config

const cacheInStatusAvailableSecond = 10
const getReviewResultMaxRetry = 5
const getReviewResultRetryInterval = 2

var rareviewClient clientset.Interface

func init() {
	config = sconfloder.NewConfig()

	log.SetFormatter(&log.JSONFormatter{})

	var err error
	k8sconfig, err := kubeutil.GetKubeConfig()
	if err != nil {
		log.Fatalf("Error getting kubeconfig: %s", err.Error())
	}
	rareviewClient, err = clientset.NewForConfig(k8sconfig)
	if err != nil {
		log.Fatalf("Error building rareview clientset: %s", err.Error())
	}
}

type ResourceResult struct {
	Object *unstructured.Unstructured `json:"object,omitempty"`
	// Result       *shield.DecisionResult     `json:"result,omitempty"`
	// CheckContext *shield.CheckContext       `json:"checkContext,omitempty"`
	Audit     bool   `json:"allowed,omitempty"`
	Protected bool   `json:"protected,omitempty"`
	Signer    string `json:"signer,omitempty"`
	Message   string `json:"message,omitempty"`
}

type AuditResult struct {
	Resources []*ResourceResult `json:"resources,omitempty"`
}

func getAge(t metav1.Time) string {
	ut := t.Time.UTC()
	dur := time.Now().UTC().Sub(ut)
	durStrBase := strings.Split(dur.String(), ".")[0] + "s"
	re := regexp.MustCompile(`\d+[a-z]`)
	age := re.FindString(durStrBase)
	return age
}

func generateResourceAuditReview(obj unstructured.Unstructured) *rareviewv1alpha1.ResourceAuditReview {
	apiVersion := obj.GetAPIVersion()
	gv, _ := schema.ParseGroupVersion(apiVersion)
	group := gv.Group
	version := gv.Version
	kind := obj.GetKind()
	namespace := obj.GetNamespace()
	name := obj.GetName()

	resAttrs := &rareviewv1alpha1.ResourceAttributes{
		Namespace: namespace,
		Group:     group,
		Version:   version,
		Kind:      kind,
		Name:      name,
	}
	nameParts := []string{group, version, strings.ToLower(kind), namespace, name}
	namePartsClean := []string{}
	for _, p := range nameParts {
		if p == "" {
			continue
		}
		namePartsClean = append(namePartsClean, p)
	}

	rarName := strings.Join(namePartsClean, "-")

	rar := &rareviewv1alpha1.ResourceAuditReview{
		ObjectMeta: metav1.ObjectMeta{
			Name: rarName,
		},
		Spec: rareviewv1alpha1.ResourceAuditReviewSpec{
			ResourceAttributes: resAttrs,
		},
	}
	return rar
}

func createResourceAuditReview(obj unstructured.Unstructured) error {
	rar := generateResourceAuditReview(obj)
	rarName := rar.GetName()

	alreadyExists := false
	current, err := rareviewClient.ApisV1alpha1().ResourceAuditReviews().Get(context.TODO(), rarName, metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			// if not found, then just create a new one
		} else {
			return err
		}
	} else {
		alreadyExists = true
	}
	if alreadyExists {
		now := time.Now().UTC()
		if now.Sub(current.Status.LastUpdated.Time) <= time.Second*cacheInStatusAvailableSecond {
			return nil
		}
	}
	if alreadyExists {
		err = rareviewClient.ApisV1alpha1().ResourceAuditReviews().Delete(context.TODO(), rarName, metav1.DeleteOptions{})
		if err != nil {
			return err
		}
	}

	_, err = rareviewClient.ApisV1alpha1().ResourceAuditReviews().Create(context.TODO(), rar, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func getResourceAuditReviewResult(obj unstructured.Unstructured) (*ResourceResult, error) {
	rar := generateResourceAuditReview(obj)
	rarName := rar.GetName()

	var err error
	var currentRar *rareviewv1alpha1.ResourceAuditReview
	for i := 0; i < getReviewResultMaxRetry; i++ {
		resultFound := false
		currentRar, err = rareviewClient.ApisV1alpha1().ResourceAuditReviews().Get(context.TODO(), rarName, metav1.GetOptions{})
		if err == nil {
			if currentRar != nil {
				if !currentRar.Status.LastUpdated.IsZero() {
					resultFound = true
				}
			}
		}
		if resultFound {
			break
		} else {
			multiplier := time.Duration(math.Pow(float64(getReviewResultRetryInterval), float64(i-2)))
			interval := time.Second * multiplier
			time.Sleep(interval)
		}
	}
	if currentRar == nil && err != nil {
		return nil, err
	}
	result := &ResourceResult{
		Object:    &obj,
		Audit:     currentRar.Status.Audit,
		Protected: currentRar.Status.Protected,
		Signer:    currentRar.Status.Signer,
		Message:   currentRar.Status.Message,
	}
	return result, nil
}

func (r *AuditResult) Table() []byte {
	tableResult := "NAME\tPROTECTED\tAUDIT_OK\tSIGNER\tAGE\t\n"
	for _, resResult := range r.Resources {
		obj := resResult.Object
		auditResult := strconv.FormatBool(resResult.Audit)
		resName := obj.GetName()
		resTime := obj.GetCreationTimestamp()
		resAge := getAge(resTime)
		protected := strconv.FormatBool(resResult.Protected)
		signer := resResult.Signer
		line := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t\n", resName, protected, auditResult, signer, resAge)
		tableResult = fmt.Sprintf("%s%s", tableResult, line)
	}
	writer := new(bytes.Buffer)
	w := tabwriter.NewWriter(writer, 0, 3, 3, ' ', 0)
	w.Write([]byte(tableResult))
	w.Flush()
	result := writer.Bytes()
	return result
}

func (r *AuditResult) DetailTable() []byte {
	tableResult := "NAME\tPROTECTED\tAUDIT_OK\tSIGNER\tRESULT\tAGE\t\n"
	for _, resResult := range r.Resources {
		obj := resResult.Object
		auditResult := strconv.FormatBool(resResult.Audit)
		resName := obj.GetName()
		resTime := obj.GetCreationTimestamp()
		resAge := getAge(resTime)
		protected := strconv.FormatBool(resResult.Protected)
		signer := resResult.Signer
		message := resResult.Message
		line := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t\n", resName, protected, auditResult, signer, message, resAge)
		tableResult = fmt.Sprintf("%s%s", tableResult, line)
	}
	writer := new(bytes.Buffer)
	w := tabwriter.NewWriter(writer, 0, 3, 3, ' ', 0)
	w.Write([]byte(tableResult))
	w.Flush()
	result := writer.Bytes()
	return result
}

func ExecKubectl(cmdpath string, args ...string) (string, error) {
	c := exec.Command(cmdpath, args...)
	outAndErr, err := c.CombinedOutput()
	if err != nil {
		return string(outAndErr), err
	}
	return string(outAndErr), nil
}

// AuditYaml does all the main cosign checks in a loop, returning validated payloads.
// If there were no payloads, we return an error.
func AuditYaml(ctx context.Context, kubectlPath string, mainArgs, kubectlArgs []string) (*AuditResult, error) {
	var err error

	tmpArgs := []string{"get", "--output", "json"}
	tmpArgs = append(tmpArgs, kubectlArgs...)
	kubectlArgs = tmpArgs

	out, err := ExecKubectl(kubectlPath, kubectlArgs...)
	if err != nil {
		return nil, errors.Wrap(err, out)
	}

	var data unstructured.Unstructured
	err = json.Unmarshal([]byte(out), &data)
	if err != nil {
		err = errors.Wrap(err, "failed to Unamrshal the returned object")
		return nil, err
	}
	var items []unstructured.Unstructured

	if data.IsList() {
		itemList, _ := data.ToList()
		for _, item := range itemList.Items {
			items = append(items, item)
		}
	} else {
		items = append(items, data)
	}
	if len(items) == 0 {
		return nil, errors.New("No resource found.")
	}

	_ = config.InitShieldConfig()

	result := &AuditResult{}
	sumErr := []string{}
	for _, obj := range items {
		err := createResourceAuditReview(obj)
		if err != nil {
			sumErr = append(sumErr, err.Error())
			continue
		}

	}
	if len(sumErr) > 0 {
		return result, errors.New(strings.Join(sumErr, "; "))
	}
	for _, obj := range items {
		resResult, err := getResourceAuditReviewResult(obj)
		if err != nil {
			sumErr = append(sumErr, err.Error())
			continue
		}
		result.Resources = append(result.Resources, resResult)
	}
	if len(sumErr) > 0 {
		return result, errors.New(strings.Join(sumErr, "; "))
	}

	return result, nil
}
