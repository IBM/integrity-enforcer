module github.com/IBM/integrity-enforcer/shield

replace github.com/docker/docker => github.com/moby/moby v0.7.3-0.20190826074503-38ab9da00309 // Required by Helm

go 1.16

require (
	github.com/IBM/integrity-enforcer/cmd v0.0.0-00010101000000-000000000000
	github.com/ghodss/yaml v1.0.0
	github.com/google/go-containerregistry v0.5.1
	github.com/jinzhu/copier v0.0.0-20190924061706-b57f9002281a
	github.com/oliveagle/jsonpath v0.0.0-20180606110733-2e52cf6e6852
	github.com/onsi/ginkgo v1.15.0
	github.com/onsi/gomega v1.11.0
	github.com/openshift/api v3.9.0+incompatible
	github.com/pkg/errors v0.9.1
	github.com/r3labs/diff v0.0.0-20191120142937-b4ed99a31f5a
	github.com/sigstore/cosign v0.4.1-0.20210602105506-5cb21aa7fbf9
	github.com/sigstore/sigstore v0.0.0-20210530211317-99216b8b86a6
	github.com/sirupsen/logrus v1.8.1
	github.com/tidwall/gjson v1.6.7
	golang.org/x/crypto v0.0.0-20210513164829-c07d793c2f9a
	gopkg.in/yaml.v2 v2.4.0
	helm.sh/helm/v3 v3.0.2
	k8s.io/api v0.21.1
	k8s.io/apimachinery v0.21.1
	k8s.io/client-go v0.20.2
	k8s.io/kube-openapi v0.0.0-20210113233702-8566a335510f
	k8s.io/kubectl v0.19.4
	sigs.k8s.io/controller-runtime v0.8.2
)

replace (
	github.com/IBM/integrity-enforcer/cmd => ../cmd
	github.com/IBM/integrity-enforcer/controller => ../controller
	github.com/IBM/integrity-enforcer/shield => ./
	//github.com/sigstore/cosign => github.com/sigstore/cosign v0.4.1-0.20210513202038-96a92e0d5c84
	github.com/sigstore/cosign => ../../../gajananan/cosign
	google.golang.org/grpc => google.golang.org/grpc v1.36.1
	k8s.io/api => k8s.io/api v0.19.0
	k8s.io/apimachinery => k8s.io/apimachinery v0.19.0
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.19.0
	k8s.io/client-go => k8s.io/client-go v0.19.0
	k8s.io/code-generator => k8s.io/code-generator v0.19.0
	k8s.io/kubectl => k8s.io/kubectl v0.19.0
	sigs.k8s.io/controller-runtime => sigs.k8s.io/controller-runtime v0.8.3
)
