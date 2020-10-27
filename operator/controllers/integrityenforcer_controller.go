//
// Copyright 2020 IBM Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package controllers

import (
	"context"
	"time"

	iev1alpha1 "github.com/IBM/integrity-enforcer/operator/api/v1alpha1"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	corev1 "k8s.io/api/core/v1"
)

var log = logf.Log.WithName("controller_integrityenforcer")

// IntegrityEnforcerReconciler reconciles a IntegrityEnforcer object
type IntegrityEnforcerReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=research.ibm.com,resources=integrityenforcers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=research.ibm.com,resources=integrityenforcers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=research.ibm.com,resources=helmreleasemetadatas,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=*,resources=resourcesignatures,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=*,resources=signpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=*,resources=enforcerconfigs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=*,resources=resourcesigningprofiles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=*,resources=clusterresourcepsigningprofiles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=*,resources=namespaces,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=*,resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=*,resources=*,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=app,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=app,resources=daemonsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=app,resources=replicasets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=app,resources=statefulsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=app,resources=deployments/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=services/finalizers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=endpoints,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=events,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=persistentvolumeclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apiextensions.k8s.io,resources=customresourcedefinitions,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=monitoring.cores.com,resources=servicemonitors,verbs=get;create
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=policy,resources=podsecuritypolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=mutationwebhookconfigurations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.openshift.io,resources=securitycontextconstraints,verbs=get;list;watch;create;update;patch;delete

func (r *IntegrityEnforcerReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	reqLogger := r.Log.WithValues("Request.Namespace", req.Namespace, "Request.Name", req.Name)

	// Fetch the IntegrityEnforcer instance
	instance := &iev1alpha1.IntegrityEnforcer{}
	err := r.Get(ctx, req.NamespacedName, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return ctrl.Result{}, err
	}

	var recResult ctrl.Result
	var recErr error

	if instance.Spec.GlobalConfig.OpenShift {
		// SecurityContextConstraints (SCC)
		recResult, recErr = r.createOrUpdateSCC(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}
	}

	// Custom Resource Definition (CRD)
	recResult, recErr = r.createOrUpdateEnforcerConfigCRD(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	recResult, recErr = r.createOrUpdateSignPolicyCRD(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	recResult, recErr = r.createOrUpdateResourceSignatureCRD(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	recResult, recErr = r.createOrUpdateResourceSigningProfileCRD(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	enabledPulgins := instance.Spec.EnforcerConfig.GetEnabledPlugins()
	if enabledPulgins["helm"] {
		recResult, recErr = r.createOrUpdateHelmReleaseMetadataCRD(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}
	}

	//Custom Resources (CR)
	recResult, recErr = r.createOrUpdateEnforcerConfigCR(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	recResult, recErr = r.createOrUpdateSignPolicyCR(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	if instance.Spec.PrimaryRsp != nil {
		recResult, recErr = r.createOrUpdatePrimaryResourceSigningProfileCR(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}
	}

	//Secret
	if instance.Spec.CertPool.CreateIfNotExist {
		recResult, recErr = r.createOrUpdateKeyringSecret(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}
	}

	// create registry secret if name and value are found in CR
	if instance.Spec.RegKeySecret.Name != "" && instance.Spec.RegKeySecret.Value != nil {
		recResult, recErr = r.createOrUpdateRegKeySecret(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}
	}

	recResult, recErr = r.createOrUpdateTlsSecret(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	//Service Account
	recResult, recErr = r.createOrUpdateServiceAccount(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	//Cluster Role
	recResult, recErr = r.createOrUpdateClusterRoleForIE(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	//Cluster Role Binding
	recResult, recErr = r.createOrUpdateClusterRoleBindingForIE(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	//Role
	recResult, recErr = r.createOrUpdateRoleForIE(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	//Role Binding
	recResult, recErr = r.createOrUpdateRoleBindingForIE(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	// ie-admin
	if !instance.Spec.Security.AutoIEAdminCreationDisabled {
		//Cluster Role
		recResult, recErr = r.createOrUpdateClusterRoleForIEAdmin(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}

		//Cluster Role Binding
		recResult, recErr = r.createOrUpdateClusterRoleBindingForIEAdmin(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}

		//Role
		recResult, recErr = r.createOrUpdateRoleForIEAdmin(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}

		//Role Binding
		recResult, recErr = r.createOrUpdateRoleBindingForIEAdmin(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}
	}

	// Pod Security Policy (PSP)
	recResult, recErr = r.createOrUpdatePodSecurityPolicy(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	// ConfigMap (RuleTable)
	recResult, recErr = r.createOrUpdateRuleTableConfigMap(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	// ConfigMap (IgnoreSATable)
	recResult, recErr = r.createOrUpdateIgnoreRuleTableConfigMap(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	// ConfigMap (ForceCheckTable)
	recResult, recErr = r.createOrUpdateForceCheckRuleTableConfigMap(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	//Deployment
	recResult, recErr = r.createOrUpdateWebhookDeployment(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	//Service
	recResult, recErr = r.createOrUpdateWebhookService(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	//Webhook Configuration
	// wait until deployment is available
	if r.isDeploymentAvailable(instance) {
		recResult, recErr = r.createOrUpdateWebhook(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}
	} else {
		recResult, recErr = r.deleteWebhook(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}
	}

	reqLogger.Info("Reconciliation successful!", "Name", instance.Name)
	// since we updated the status in the CR, sleep 5 seconds to allow the CR to be refreshed.
	time.Sleep(5 * time.Second)

	return ctrl.Result{}, nil

}

func (r *IntegrityEnforcerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&iev1alpha1.IntegrityEnforcer{}).
		Owns(&corev1.Pod{}).
		Complete(r)
}
