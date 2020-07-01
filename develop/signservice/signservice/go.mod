module github.com/IBM/integrity-enforcer/develop/signservice/signservice

go 1.14

require (
	github.com/ghodss/yaml v1.0.0
	github.com/gorilla/mux v1.7.0
	github.com/sirupsen/logrus v1.6.0
	github.com/IBM/integrity-enforcer/enforcer v0.0.0-20200602121605-c0fa868d3900
	k8s.io/apimachinery v0.18.2
)

replace (
	github.com/docker/docker => github.com/moby/moby v0.7.3-0.20190826074503-38ab9da00309 // Required by Helm
	github.com/IBM/integrity-enforcer/develop/signservice/signservice/pkg/cert => ./pkg/cert
	github.com/IBM/integrity-enforcer/develop/signservice/signservice/pkg/sign => ./pkg/sign
	github.com/IBM/integrity-enforcer/enforcer => ../../../enforcer
	k8s.io/api => k8s.io/api v0.16.5-beta.1
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.16.5-beta.1
	k8s.io/apimachinery => k8s.io/apimachinery v0.16.5-beta.1
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.16.5-beta.1
	k8s.io/client-go => k8s.io/client-go v0.16.5-beta.1
	k8s.io/kubectl => k8s.io/kubectl v0.16.5-beta.1
)
