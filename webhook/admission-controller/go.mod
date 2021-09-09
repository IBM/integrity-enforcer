module github.com/IBM/integrity-shield/webhook/admission-controller

go 1.16

require (
	github.com/IBM/integrity-shield/shield v0.0.0-00010101000000-000000000000
	github.com/ghodss/yaml v1.0.0
	github.com/jinzhu/copier v0.3.2
	github.com/pkg/errors v0.9.1
	github.com/sigstore/k8s-manifest-sigstore v0.0.0-20210909071548-2120192e4ff7
	github.com/sirupsen/logrus v1.8.1
	k8s.io/api v0.21.3
	k8s.io/apimachinery v0.21.3
	k8s.io/client-go v0.21.3
	sigs.k8s.io/controller-runtime v0.9.0
)

replace (
	github.com/IBM/integrity-shield/shield => ../../shield
	github.com/IBM/integrity-shield/webhook/admission-controller => ./
	k8s.io/kubectl => k8s.io/kubectl v0.21.2

)
