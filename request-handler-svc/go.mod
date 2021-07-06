module github.com/IBM/integrity-shield/reqhandler-svc

go 1.16

require (
	github.com/IBM/integrity-shield/admission-controller v0.0.0-20210623045136-c45f25989778
	github.com/sirupsen/logrus v1.8.1
	sigs.k8s.io/controller-runtime v0.9.0
)

replace (
	github.com/IBM/integrity-shield/admission-controller => ../admission-controller
	github.com/IBM/integrity-shield/reqhandler-svc => ./
	github.com/sigstore/cosign => github.com/sigstore/cosign v0.4.1-0.20210602105506-5cb21aa7fbf9
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
