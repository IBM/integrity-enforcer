package audit

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	_ "embed" // To enable the `go:embed` directive.

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	sconfloder "github.com/IBM/integrity-enforcer/shield/pkg/config/loader"
	"github.com/IBM/integrity-enforcer/shield/pkg/shield"
	"github.com/IBM/integrity-enforcer/shield/pkg/util/kubeutil"
	"github.com/IBM/integrity-enforcer/shield/pkg/util/logger"
	"github.com/pkg/errors"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
)

const IntegrityShieldAnnotationMessage = "integrityshield.io/message"
const IntegrityShieldAnnotationSignature = "integrityshield.io/signature"
const IntegrityShieldAnnotationCertificate = "integrityshield.io/certificate"

var config *sconfloder.Config

func init() {
	config = sconfloder.NewConfig()

	log.SetFormatter(&log.JSONFormatter{})
}

func getTlogEntry(rekorClient *client.Rekor, uuid string) (*models.LogEntryAnon, error) {
	params := entries.NewGetLogEntryByUUIDParams()
	params.SetEntryUUID(uuid)
	resp, err := rekorClient.Entries.GetLogEntryByUUID(params)
	if err != nil {
		return nil, err
	}
	for _, e := range resp.Payload {
		return &e, nil
	}
	return nil, errors.New("empty response")
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
	resourceHandler := shield.NewResourceHandler(config.ShieldConfig, metaLogger, reqLog)

	var obj *unstructured.Unstructured
	obj, err := kubeutil.GetResource(apiVersion, kind, namespace, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get the specified resource; %s", err.Error())
	}
	dr = resourceHandler.Run(obj)
	return dr, nil
}

func checkExpiry(cert *x509.Certificate, it time.Time) error {
	ft := func(t time.Time) string {
		return t.Format(time.RFC3339)
	}
	if cert.NotAfter.Before(it) {
		return fmt.Errorf("certificate expired before signatures were entered in log: %s is before %s",
			ft(cert.NotAfter), ft(it))
	}
	if cert.NotBefore.After(it) {
		return fmt.Errorf("certificate was issued after signatures were entered in log: %s is after %s",
			ft(cert.NotAfter), ft(it))
	}
	return nil
}

func correctAnnotations(wanted, have map[string]interface{}) bool {
	for k, v := range wanted {
		if have[k] != v {
			return false
		}
	}
	return true
}
