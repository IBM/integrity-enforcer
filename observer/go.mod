module github.com/IBM/integrity-enforcer/observer

go 1.16

require (
	github.com/IBM/integrity-enforcer/shield v0.0.0-20201001024601-320551d946dc
	github.com/ghodss/yaml v1.0.1-0.20190212211648-25d852aebe32 // indirect
	github.com/go-logr/logr v0.2.1 // indirect
	github.com/hpcloud/tail v1.0.0
	github.com/jasonlvhit/gocron v0.0.1
	github.com/onsi/ginkgo v1.14.2 // indirect
	github.com/onsi/gomega v1.10.3 // indirect
	github.com/sirupsen/logrus v1.7.0
	k8s.io/api v0.20.2
	k8s.io/apimachinery v0.20.2
	k8s.io/client-go v12.0.0+incompatible
)

replace (
	github.com/IBM/integrity-enforcer/observer => ./
	github.com/IBM/integrity-enforcer/shield => ../shield
	k8s.io/api => k8s.io/api v0.19.0
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.19.0
	k8s.io/apimachinery => k8s.io/apimachinery v0.19.0
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.19.0
	k8s.io/client-go => k8s.io/client-go v0.19.0
	k8s.io/kubectl => k8s.io/kubectl v0.19.0
	sigs.k8s.io/controller-runtime => sigs.k8s.io/controller-runtime v0.6.2
)

replace github.com/docker/docker => github.com/moby/moby v0.7.3-0.20190826074503-38ab9da00309 // Required by Helm

replace github.com/openshift/api => github.com/openshift/api v0.0.0-20190924102528-32369d4db2ad // Required until https://github.com/operator-framework/operator-lifecycle-manager/pull/1241 is resolved
