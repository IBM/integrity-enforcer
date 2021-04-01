module github.com/IBM/integrity-enforcer/inspector

go 1.15

require (
	github.com/IBM/integrity-enforcer/shield v0.0.0-00010101000000-000000000000
	k8s.io/apimachinery v0.18.6
	k8s.io/client-go v0.18.6
)

replace (
	github.com/IBM/integrity-enforcer/inspector => ./
	github.com/IBM/integrity-enforcer/shield => ../shield
	k8s.io/api => k8s.io/api v0.18.6
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.18.6
	k8s.io/apimachinery => k8s.io/apimachinery v0.18.6
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.18.6
	k8s.io/client-go => k8s.io/client-go v0.18.6
	k8s.io/code-generator => k8s.io/code-generator v0.18.6
	k8s.io/kubectl => k8s.io/kubectl v0.18.6
	sigs.k8s.io/controller-runtime => sigs.k8s.io/controller-runtime v0.6.2
)

replace github.com/docker/docker => github.com/moby/moby v0.7.3-0.20190826074503-38ab9da00309 // Required by Helm
