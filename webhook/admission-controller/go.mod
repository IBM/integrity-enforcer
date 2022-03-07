module github.com/stolostron/integrity-shield/webhook/admission-controller

go 1.16

require (
	github.com/ghodss/yaml v1.0.0
	github.com/jinzhu/copier v0.3.2
	github.com/pkg/errors v0.9.1
	github.com/sigstore/cosign v1.5.2
	github.com/sigstore/k8s-manifest-sigstore v0.2.1-0.20220304050627-ed26e30c7343
	github.com/sirupsen/logrus v1.8.1
	github.com/stolostron/integrity-shield/shield v0.0.0-00010101000000-000000000000
	k8s.io/api v0.23.0
	k8s.io/apimachinery v0.23.0
	k8s.io/client-go v0.23.0
	sigs.k8s.io/controller-runtime v0.11.0-beta.0.0.20211115163949-4d10a0615b11
)

replace (
	github.com/stolostron/integrity-shield/shield => ../../shield
	github.com/stolostron/integrity-shield/webhook/admission-controller => ./
)
