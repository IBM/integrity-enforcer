# How to Sign Resources

## Sign Type

IE supports two modes of signature verification.
- `pgp`: use [gpg key](https://www.gnupg.org/index.html) for signing. certificate is not used.
- `x509`: use signing key with X509 public key certificate.

`spec.verifyType` should be set either `pgp` (default) or `x509`.

```
apiVersion: apis.integrityenforcer.io/v1alpha1
kind: IntegrityEnforcer
metadata:
  name: integrity-enforcer-server
spec:
  verifyType: pgp
```

## Setup

IE requires a secret that includes a pubkey ring for verifying signatures of resources that need to be protected.  IE supports X509 or PGP key for signing resources. For X509 mode, a certificate is supplied along with signature and CA certificate is used to verify the validiy of the given certificate. CA certifivate need to be registered to setup IE. For PGP mode, no certificate is used. Instead, public keys for verifying signature need to be registered to setup IE. The following steps show how you can import your keys or certificates to IE.

### PGP mode

First, you need to export public key to a file. The following example shows a pubkey for a signer identified by an email `signer@enterprise.com` is exported and stored in `/tmp/pubring.gpg`. (Use the filename `pubring.gpg`.)

```
$ gpg --export signer@enterprise.com > /tmp/pubring.gpg
```

If you do not have any PGP key or you want to use new key, generate new one and export it to a file. See [this GitHub document](https://docs.github.com/en/free-pro-team@latest/github/authenticating-to-github/generating-a-new-gpg-key).

Then, create a secret that includes a pubkey ring for verifying signatures of resources

```
oc create secret generic --save-config keyring-secret  -n integrity-enforcer-ns --from-file=/tmp/pubring.gpg
```

You can run `scripts/gpg-rs-sign.sh` script to generate ResourceSignature YAML file which includes signature for a Yaml file. For example,

```
$ ./scripts/gpg-rs-sign.sh signer@enterprise.com /tmp/test-cm.yaml /tmp/test-cm-rs.yaml
```

The ResourceSignature resource must be created to allow admission with the YAML.

`ResourceSignature` resource has a `message` field which refers to the encoded content of a resource file to be signed. A resource file may include a specification for single resource or multiple resources. A signature is generated for the entire YAML file, but it is used to verify when any resources are verified with the signature if the resource is to be protected according to ResourceSigningProfile (RSP).

