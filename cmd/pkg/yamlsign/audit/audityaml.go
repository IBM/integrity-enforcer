package audit

import (
	"context"
	"fmt"

	_ "embed" // To enable the `go:embed` directive.

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	sconfloder "github.com/IBM/integrity-enforcer/shield/pkg/config/loader"
	"github.com/IBM/integrity-enforcer/shield/pkg/shield"
	"github.com/IBM/integrity-enforcer/shield/pkg/util/kubeutil"
	"github.com/IBM/integrity-enforcer/shield/pkg/util/logger"
)

var config *sconfloder.Config

func init() {
	config = sconfloder.NewConfig()

	log.SetFormatter(&log.JSONFormatter{})
}

// AuditYaml does all the main cosign checks in a loop, returning validated payloads.
// If there were no payloads, we return an error.
func AuditYaml(ctx context.Context, apiVersion, kind, namespace, name string) (*shield.DecisionResult, error) {
	var dr *shield.DecisionResult

	_ = config.InitShieldConfig()

	metaLogger := logger.NewLogger(config.ShieldConfig.LoggerConfig())
	reqLog := metaLogger.WithFields(
		log.Fields{
			"namespace":  namespace,
			"name":       name,
			"apiVersion": apiVersion,
			"kind":       kind,
		},
	)
	resourceHandler := shield.NewResourceCheckHandler(config.ShieldConfig, metaLogger, reqLog)

	var obj *unstructured.Unstructured
	obj, err := kubeutil.GetResource(apiVersion, kind, namespace, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get the specified resource; %s", err.Error())
	}
	dr = resourceHandler.Run(obj)
	return dr, nil
}
