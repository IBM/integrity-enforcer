module github.com/IBM/integrity-enforcer/develop/signservice/signservice-operator

go 1.13

require (
	github.com/ghodss/yaml v1.0.1-0.20190212211648-25d852aebe32
	github.com/google/go-cmp v0.4.0
	github.com/operator-framework/operator-sdk v0.17.0
	github.com/spf13/pflag v1.0.5
	github.com/IBM/integrity-enforcer/enforcer v0.0.0-20200526092602-9fe2166392e1
	github.com/IBM/integrity-enforcer/operator v0.0.0-20200602121605-c0fa868d3900
	golang.org/x/crypto v0.0.0-20200128174031-69ecbb4d6d5d
	k8s.io/api v0.18.0
	k8s.io/apimachinery v0.18.0
	k8s.io/client-go v12.0.0+incompatible
	sigs.k8s.io/controller-runtime v0.5.2
)

// Pinned to kubernetes-1.16.2
replace (
	github.com/IBM/integrity-enforcer/enforcer => ../../../enforcer
	github.com/IBM/integrity-enforcer/operator => ../../../operator
	github.com/Azure/go-autorest => github.com/Azure/go-autorest v13.3.4-0.20200207053602-7439e774c9e9+incompatible
	k8s.io/api => k8s.io/api v0.16.5-beta.1
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.16.5-beta.1
	k8s.io/apimachinery => k8s.io/apimachinery v0.16.5-beta.1
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.16.5-beta.1
	k8s.io/client-go => k8s.io/client-go v0.16.5-beta.1
	k8s.io/kubectl => k8s.io/kubectl v0.16.5-beta.1
)

replace github.com/docker/docker => github.com/moby/moby v0.7.3-0.20190826074503-38ab9da00309 // Required by Helm

replace github.com/openshift/api => github.com/openshift/api v0.0.0-20190924102528-32369d4db2ad // Required until https://github.com/operator-framework/operator-lifecycle-manager/pull/1241 is resolved
