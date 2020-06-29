module github.com/IBM/integrity-enforcer/operator

go 1.13

require (
	github.com/ghodss/yaml v1.0.1-0.20190212211648-25d852aebe32
	github.com/google/go-cmp v0.4.0
	github.com/openshift/api v0.0.0-20200205133042-34f0ec8dab87
	github.com/operator-framework/operator-sdk v0.17.0
	github.com/spf13/pflag v1.0.5
	github.com/IBM/integrity-enforcer/enforcer v0.0.0-20200526092602-9fe2166392e1
	golang.org/x/crypto v0.0.0-20200128174031-69ecbb4d6d5d
	k8s.io/api v0.18.0
	k8s.io/apiextensions-apiserver v0.18.0
	k8s.io/apimachinery v0.18.0
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/utils v0.0.0-20200117235808-5f6fbceb4c31 // indirect
	sigs.k8s.io/controller-runtime v0.5.2
)

replace (
	github.com/Azure/go-autorest => github.com/Azure/go-autorest v13.3.4-0.20200207053602-7439e774c9e9+incompatible
	k8s.io/api => k8s.io/api v0.16.5-beta.1
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.16.5-beta.1
	k8s.io/apimachinery => k8s.io/apimachinery v0.16.5-beta.1
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.16.5-beta.1
	k8s.io/client-go => k8s.io/client-go v0.16.5-beta.1
	k8s.io/kubectl => k8s.io/kubectl v0.16.5-beta.1
	github.com/IBM/integrity-enforcer/enforcer => ../enforcer
)

replace github.com/docker/docker => github.com/moby/moby v0.7.3-0.20190826074503-38ab9da00309 // Required by Helm

replace github.com/openshift/api => github.com/openshift/api v0.0.0-20190924102528-32369d4db2ad // Required until https://github.com/operator-framework/operator-lifecycle-manager/pull/1241 is resolved
