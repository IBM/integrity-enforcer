module github.com/IBM/integrity-enforcer/observer

go 1.16

require (
	github.com/IBM/integrity-shield/observer v0.0.0-00010101000000-000000000000
	github.com/IBM/integrity-shield/shield v0.0.0-00010101000000-000000000000
	github.com/pkg/errors v0.9.1
	github.com/sigstore/k8s-manifest-sigstore v0.0.0-20210909071548-2120192e4ff7
	github.com/sirupsen/logrus v1.8.1
	k8s.io/api v0.21.3
	k8s.io/apimachinery v0.21.3
	k8s.io/client-go v0.21.3
)

replace (
	github.com/IBM/integrity-shield/observer => ./
	github.com/IBM/integrity-shield/shield => ../shield
	github.com/IBM/integrity-shield/webhook/admission-controller => ../webhook/admission-controller
	k8s.io/kubectl => k8s.io/kubectl v0.21.2

)

replace github.com/docker/docker => github.com/moby/moby v0.7.3-0.20190826074503-38ab9da00309 // Required by Helm
