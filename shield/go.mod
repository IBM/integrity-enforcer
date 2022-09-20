module github.com/stolostron/integrity-shield/shield

go 1.16

require (
	github.com/ghodss/yaml v1.0.0
	github.com/jinzhu/copier v0.3.2
	github.com/pkg/errors v0.9.1
	github.com/sigstore/cosign v1.12.0
	github.com/sigstore/k8s-manifest-sigstore v0.4.0
	github.com/sirupsen/logrus v1.9.0
	k8s.io/api v0.25.0-alpha.2
	k8s.io/apimachinery v0.25.0-alpha.2
	k8s.io/client-go v0.25.0-alpha.2
	sigs.k8s.io/controller-runtime v0.12.2
)

replace github.com/stolostron/integrity-shield/shield => ./

replace (
	github.com/open-policy-agent/opa => github.com/open-policy-agent/opa v0.44.0
	k8s.io/kubectl => k8s.io/kubectl v0.25.0-alpha.2
)
