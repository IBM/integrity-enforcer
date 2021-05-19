module github.com/IBM/integrity-enforcer/cmd

go 1.16

require (
	github.com/IBM/integrity-enforcer/shield v0.0.0-00010101000000-000000000000
	github.com/ghodss/yaml v1.0.0
	github.com/google/go-containerregistry v0.5.0
	github.com/peterbourgon/ff/v3 v3.0.0
	github.com/pkg/errors v0.9.1
	github.com/sigstore/cosign v0.4.0
	github.com/sigstore/rekor v0.1.2-0.20210428010952-9e3e56d52dd0
	github.com/sigstore/sigstore v0.0.0-20210516171352-bee6a385d4af
	github.com/sirupsen/logrus v1.7.0
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/apimachinery v0.20.2
)

replace (
	github.com/IBM/integrity-enforcer/cmd => ./
	github.com/IBM/integrity-enforcer/shield => ../shield
	github.com/sigstore/cosign => github.com/sigstore/cosign v0.4.1-0.20210513202038-96a92e0d5c84
	k8s.io/api => k8s.io/api v0.19.0
	k8s.io/apimachinery => k8s.io/apimachinery v0.19.0
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.19.0
	k8s.io/client-go => k8s.io/client-go v0.19.0
	k8s.io/code-generator => k8s.io/code-generator v0.19.0
	k8s.io/kubectl => k8s.io/kubectl v0.19.0
)

replace github.com/docker/docker => github.com/moby/moby v0.7.3-0.20190826074503-38ab9da00309 // Required by Helm
