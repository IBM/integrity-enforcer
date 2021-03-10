
# Upgrade OCP Cluster while Integrity Shield is running

OpenShift Container Platform (OCP) has a cluster upgrade function for an existing OCP cluster, and of course this is available even if Integrity Shield is running.

However, during this upgrade, components such as pods, Kubernetes API server and some others will be unavailable for a while.

So this could make Integrity Shield protection unavailable just for a while (a few minutes normally). For details of this, please refer to [this](../README_LIMITATION.md).

Please note that signature protection would be disabled temporally during OCP cluster upgrade.
