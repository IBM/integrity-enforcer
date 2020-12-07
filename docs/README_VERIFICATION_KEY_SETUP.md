# How to setup a verification key.

## Verification Key setup
Integrity Verifier 
A secret resource (keyring-secret) which contains public key and certificates should be setup in a cluster for enabling signature verification by Integrity Verifier. We describe how we could setup a verification key as below.

### Verification key Type
`pgp`: use [gpg key](https://www.gnupg.org/index.html) for signing.

### PGP Key Setup

First, you need to export a public key to a file. The following example shows a pubkey for a signer identified by an email `signer@enterprise.com` is exported and stored in `/tmp/pubring.gpg`. (Use the filename `pubring.gpg`.)

```
$ gpg --export signer@enterprise.com > /tmp/pubring.gpg
```

If you do not have any PGP key or you want to use new key, generate new one and export it to a file. See [this GitHub document](https://docs.github.com/en/free-pro-team@latest/github/authenticating-to-github/generating-a-new-gpg-key).

