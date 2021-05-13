module github.com/ibm/integrity-enforcer/cmd

go 1.16

require (
	github.com/IBM/integrity-enforcer/cmd v0.0.0-00010101000000-000000000000
	github.com/ghodss/yaml v1.0.0
	github.com/google/go-containerregistry v0.5.0
	github.com/peterbourgon/ff/v3 v3.0.0
	github.com/pkg/errors v0.9.1
	github.com/sigstore/cosign v0.4.0
	github.com/sigstore/rekor v0.1.2-0.20210428010952-9e3e56d52dd0
	github.com/sigstore/sigstore v0.0.0-20210427115853-11e6eaab7cdc
	gopkg.in/yaml.v2 v2.4.0
)

replace github.com/IBM/integrity-enforcer/cmd => ./
