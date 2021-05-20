package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
	"github.com/IBM/integrity-enforcer/shield/pkg/util/logger"
)

var config *sconfloder.Config

func init() {
	config = sconfloder.NewConfig()

	log.SetFormatter(&log.JSONFormatter{})
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

func (r *AuditResult) Table() []byte {
	tableResult := "NAME\tAUDIT\tPROTECTED\tSIGNER\tAGE\t\n"
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
	var dr *shield.DecisionResult
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
	for i, obj := range items {
		metaLogger := logger.NewLogger(config.ShieldConfig.LoggerConfig())
		resourceHandler := shield.NewResourceCheckHandler(config.ShieldConfig, metaLogger)
		dr = resourceHandler.Run(&obj)
		ctx := resourceHandler.GetCheckContext()
		objPtr := &(items[i])
		res := &ResourceResult{Object: objPtr, Result: dr, CheckContext: ctx}
		result.Resources = append(result.Resources, res)
	}

	return result, nil
}
