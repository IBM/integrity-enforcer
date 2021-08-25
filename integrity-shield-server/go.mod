module github.com/IBM/integrity-shield/integrity-shield-server

go 1.16

require (
	github.com/ghodss/yaml v1.0.0
	github.com/jinzhu/copier v0.3.2
	github.com/pkg/errors v0.9.1
	github.com/sigstore/k8s-manifest-sigstore v0.0.0-20210820081408-1767e96c5fe2
	github.com/sirupsen/logrus v1.8.1
	k8s.io/api v0.21.3
	k8s.io/apimachinery v0.21.3
	k8s.io/client-go v0.21.3
	sigs.k8s.io/controller-runtime v0.9.0
)

replace (
	github.com/IBM/integrity-shield/integrity-shield-server => ./
	k8s.io/kubectl => k8s.io/kubectl v0.21.2
)

// replace github.com/docker/docker => github.com/moby/moby v0.7.3-0.20190826074503-38ab9da00309 // Required by Helm
