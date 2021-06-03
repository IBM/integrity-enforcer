module github.com/IBM/integrity-enforcer/controller

go 1.16

require (
	github.com/IBM/integrity-enforcer/shield v0.0.0-00010101000000-000000000000
	k8s.io/api v0.21.1
	k8s.io/apimachinery v0.21.1
	k8s.io/client-go v0.20.2
	k8s.io/klog/v2 v2.5.0
)

replace (
	github.com/IBM/integrity-enforcer/api => ../api
	github.com/IBM/integrity-enforcer/cmd => ../cmd
	github.com/IBM/integrity-enforcer/controller => ./
	github.com/IBM/integrity-enforcer/shield => ../shield
	github.com/sigstore/cosign => ../../../gajananan/cosign
	k8s.io/api => k8s.io/api v0.19.0
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.19.0
	k8s.io/apimachinery => k8s.io/apimachinery v0.19.0
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.19.0
	k8s.io/client-go => k8s.io/client-go v0.19.0
	k8s.io/code-generator => k8s.io/code-generator v0.19.0
	k8s.io/kubectl => k8s.io/kubectl v0.19.0
	sigs.k8s.io/controller-runtime => sigs.k8s.io/controller-runtime v0.8.3
)

replace github.com/docker/docker => github.com/moby/moby v0.7.3-0.20190826074503-38ab9da00309 // Required by Helm
