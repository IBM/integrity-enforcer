package audit

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	_ "embed" // To enable the `go:embed` directive.

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	sconfloder "github.com/IBM/integrity-enforcer/shield/pkg/config/loader"
	"github.com/IBM/integrity-enforcer/shield/pkg/shield"
)

var config *sconfloder.Config

const ishieldAPIEnvName = "ISHIELD_API_URL"
const defaultAPIURL = "https://default-ishield-api:8123"

var apiURL string
var httpClient *http.Client

func init() {
	config = sconfloder.NewConfig()

	log.SetFormatter(&log.JSONFormatter{})

	apiURL = os.Getenv(ishieldAPIEnvName)
	if apiURL == "" {
		apiURL = defaultAPIURL
	}

	httpClient = new(http.Client)
	httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
}

type ResourceResult struct {
	Object       *unstructured.Unstructured `json:"object,omitempty"`
	Result       *shield.DecisionResult     `json:"result,omitempty"`
	CheckContext *shield.CheckContext       `json:"checkContext,omitempty"`
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

func GetIshieldAPIBaseURL() string {
	return apiURL
}

func parseResourceAPIResult(result []byte) (*shield.DecisionResult, *shield.CheckContext) {
	var dr *shield.DecisionResult
	var ctx *shield.CheckContext

	var m map[string]interface{}
	_ = json.Unmarshal(result, &m)
	drB, _ := json.Marshal(m["result"])
	ctxB, _ := json.Marshal(m["context"])
	// fmt.Println("[DEBUG] drB: ", string(drB))
	// fmt.Println("[DEBUG] ctxB: ", string(ctxB))
	_ = json.Unmarshal(drB, &dr)
	_ = json.Unmarshal(ctxB, &ctx)
	return dr, ctx
}

func callResourceCheckAPI(obj unstructured.Unstructured) (*shield.DecisionResult, *shield.CheckContext, error) {
	url := GetIshieldAPIBaseURL() + "/api/resource"
	objB, _ := json.Marshal(obj.Object)
	dataB := bytes.NewBuffer(objB)

	req, err := http.NewRequest("POST", url, dataB)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Add("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	result, err := ioutil.ReadAll(resp.Body)
	// fmt.Println("[DEBUG] result: ", string(result))
	if err != nil {
		return nil, nil, err
	}

	dr, ctx := parseResourceAPIResult(result)

	return dr, ctx, nil
}

func (r *AuditResult) Table() []byte {
	tableResult := "NAME\tAUDIT_OK\tPROTECTED\tSIGNER\tAGE\t\n"
	for _, resResult := range r.Resources {
		obj := resResult.Object
		dr := resResult.Result
		ctx := resResult.CheckContext
		auditResult := strconv.FormatBool(dr.IsAllowed())
		resName := obj.GetName()
		resTime := obj.GetCreationTimestamp()
		resAge := getAge(resTime)
		protected := strconv.FormatBool(ctx.Protected)
		signer := ctx.SignatureEvalResult.SignerName
		line := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t\n", resName, auditResult, protected, signer, resAge)
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
	for i, obj := range items {
		dr, ctx, err := callResourceCheckAPI(obj)
		if err != nil {
			sumErr = append(sumErr, err.Error())
			continue
		}
		objPtr := &(items[i])
		res := &ResourceResult{Object: objPtr, Result: dr, CheckContext: ctx}
		result.Resources = append(result.Resources, res)
	}
	if len(sumErr) > 0 {
		return result, errors.New(strings.Join(sumErr, "; "))
	}

	return result, nil
}
