# Limitation

## Signature Protection Availability  


Signature protection provided by Integrity Shield requires 2 veriy essential pieces - first one is of course Integrity Shield itself running in a cluster, and another one is a Kubernetes API server which is accessible from Integrity Shield.

Therefore, signatures are not verified while Integrity Shield is not deployed or not correctly running. Also, the protection might not be triggered if the Kubernetes API server has problem or it is in some unhealthy state.