module github.com/IBM/integrity-enforcer/enforcer

replace github.com/docker/docker => github.com/moby/moby v0.7.3-0.20190826074503-38ab9da00309 // Required by Helm

go 1.13

require (
	github.com/ghodss/yaml v1.0.0
	github.com/jinzhu/copier v0.0.0-20190924061706-b57f9002281a
	github.com/oliveagle/jsonpath v0.0.0-20180606110733-2e52cf6e6852
	github.com/pkg/errors v0.9.1
	github.com/r3labs/diff v0.0.0-20191120142937-b4ed99a31f5a
	github.com/sirupsen/logrus v1.4.2
	github.com/tidwall/gjson v1.5.0
	golang.org/x/crypto v0.0.0-20200128174031-69ecbb4d6d5d
	gopkg.in/yaml.v2 v2.2.8
	helm.sh/helm/v3 v3.0.2
	k8s.io/api v0.16.5-beta.1
	k8s.io/apiextensions-apiserver v0.16.5-beta.1
	k8s.io/apimachinery v0.16.5-beta.1
	k8s.io/client-go v0.16.5-beta.1
)


replace (
	k8s.io/api => k8s.io/api v0.16.5-beta.1
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.16.5-beta.1
	k8s.io/apimachinery => k8s.io/apimachinery v0.16.5-beta.1
	k8s.io/client-go => k8s.io/client-go v0.16.5-beta.1
	k8s.io/code-generator => k8s.io/code-generator v0.16.5-beta.1
)
