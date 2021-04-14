package sigstore

import (
	"testing"
)

func TestVerifyPayload(t *testing.T) {

	testMsg := []byte(`apiVersion: v1
kind: ConfigMap
metadata:
  name: sample-cm
data:
  key1: val1
  key2: val2	
`)
	testEncodedSig := []byte(`MEYCIQCsvveUpURqfvRRTrceW/+gl8Hp6CRn/XspMGbD+szuXAIhAMJslDsB2kWLshFqfQk/gqGorImBvZLw/YJvCLNN1UUa`)
	testSig := []byte(base64decode(testEncodedSig))

	testCert := []byte(`-----BEGIN CERTIFICATE-----
MIICyTCCAk+gAwIBAgIUAPjnu+Y0IDZKAXxEyolLgh8/+UwwCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MTA0MTMwMTM3MjJaFw0yMTA0MTMwMTU3MjJaMEwxJDAiBgNVBAoMG2hpcm9rdW5p
LmtpdGFoYXJhQGdtYWlsLmNvbTEkMCIGA1UEAwwbaGlyb2t1bmkua2l0YWhhcmFA
Z21haWwuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELeZINQPAWLgovI+S
VMKb2OWRw1vOllhZmZmBdoWxF4OI8hiHdm2or+GPjGpq/Fz8HDDhB4oyLi3WiF23
Yt69cqOCAS8wggErMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcD
AzAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBT4ytlLze0LBNvcscSCK92Ke1rw4DAf
BgNVHSMEGDAWgBTIxR0AQZokKTJRJOsNrkrtSgbT7DCBjQYIKwYBBQUHAQEEgYAw
fjB8BggrBgEFBQcwAoZwaHR0cDovL3ByaXZhdGVjYS1jb250ZW50LTYwM2ZlN2U3
LTAwMDAtMjIyNy1iZjc1LWY0ZjVlODBkMjk1NC5zdG9yYWdlLmdvb2dsZWFwaXMu
Y29tL2NhMzZhMWU5NjI0MmI5ZmNiMTQ2L2NhLmNydDAmBgNVHREEHzAdgRtoaXJv
a3VuaS5raXRhaGFyYUBnbWFpbC5jb20wCgYIKoZIzj0EAwMDaAAwZQIwRjRGSLcW
TaKSUYMH3iMOxMm28gtyYicAHCKeBaApXYGK1bewsLtpBLcJHPECFxAkAjEAic3B
ki9IigC5WSG5K/a384OxS09vNWuSH0bIJsxhHnSnryQ0euF3Ivo0b0UYL+lj
-----END CERTIFICATE-----
`)

	ok, err := Verify(testMsg, testSig, testCert, nil)
	if err != nil {
		t.Errorf("failed to verify tlog; %s", err.Error())
	} else {
		t.Log("succeeded to verify tlog!", ok)
	}

}
