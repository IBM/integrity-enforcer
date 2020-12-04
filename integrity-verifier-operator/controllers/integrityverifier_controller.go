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
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	apisv1alpha1 "github.com/IBM/integrity-enforcer/integrity-verifier-operator/api/v1alpha1"
	"github.com/IBM/integrity-enforcer/integrity-verifier-operator/resources"
)

var log = logf.Log.WithName("controller_integrityverifier")

// IntegrityVerifierReconciler reconciles a IntegrityVerifier object
type IntegrityVerifierReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=core,resources=pods;services;serviceaccounts;services/finalizers;endpoints;persistentvolumeclaims;events;configmaps;secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=namespaces,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=apps,resources=deployments;daemonsets;replicasets;statefulsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=monitoring.coreos.com,resources=servicemonitors,verbs=get;create
// +kubebuilder:rbac:groups=apps,resources=deployments/finalizers,resourceNames=integrity-verifier-operator,verbs=update
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get
// +kubebuilder:rbac:groups=apps,resources=deployments;replicasets,verbs=get
// +kubebuilder:rbac:groups=apis.integrityverifier.io,resources=integrityverifiers;integrityverifiers/finalizers;verifierconfigs;signpolicies;resourcesigningprofiles;resourcesignatures;helmreleasemetadatas,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apiextensions.k8s.io,resources=customresourcedefinitions,verbs=*
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles;clusterrolebindings;roles;rolebindings,verbs=*
// +kubebuilder:rbac:groups=policy,resources=podsecuritypolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=mutatingwebhookconfigurations,verbs=*

func (r *IntegrityVerifierReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	reqLogger := r.Log.WithValues("Request.Namespace", req.Namespace, "Request.Name", req.Name)

	// Fetch the IntegrityVerifier instance
	instance := &apisv1alpha1.IntegrityVerifier{}
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

	// apply default config if not ignored
	if !instance.Spec.IgnoreDefaultIVCR {
		instance = resources.MergeDefaultIntegrityVerifierCR(instance, "")
	}

	if ok, nonReadyKey := r.isKeyRingReady(instance); !ok {
		reqLogger.Info(fmt.Sprintf("KeyRing secret \"%s\" does not exist. Skip reconciling.", nonReadyKey))
		return ctrl.Result{Requeue: true}, nil
	}

	// Custom Resource Definition (CRD)
	recResult, recErr = r.createOrUpdateVerifierConfigCRD(instance)
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

	enabledPulgins := instance.Spec.VerifierConfig.GetEnabledPlugins()
	if enabledPulgins["helm"] {
		recResult, recErr = r.createOrUpdateHelmReleaseMetadataCRD(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}
	}

	//Custom Resources (CR)
	recResult, recErr = r.createOrUpdateVerifierConfigCR(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	recResult, recErr = r.createOrUpdateSignPolicyCR(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	if len(instance.Spec.ResourceSigningProfiles) > 0 {
		for _, prof := range instance.Spec.ResourceSigningProfiles {
			recResult, recErr = r.createOrUpdateResourceSigningProfileCR(instance, prof)
			if recErr != nil || recResult.Requeue {
				return recResult, recErr
			}
		}
	}

	//Secret
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
	recResult, recErr = r.createOrUpdateClusterRoleForIV(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	//Cluster Role Binding
	recResult, recErr = r.createOrUpdateClusterRoleBindingForIV(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	//Role
	recResult, recErr = r.createOrUpdateRoleForIV(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	//Role Binding
	recResult, recErr = r.createOrUpdateRoleBindingForIV(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	// iv-admin
	if !instance.Spec.Security.AutoIVAdminCreationDisabled {
		//Cluster Role
		recResult, recErr = r.createOrUpdateClusterRoleForIVAdmin(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}

		//Cluster Role Binding
		recResult, recErr = r.createOrUpdateClusterRoleBindingForIVAdmin(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}

		//Role
		recResult, recErr = r.createOrUpdateRoleForIVAdmin(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}

		//Role Binding
		recResult, recErr = r.createOrUpdateRoleBindingForIVAdmin(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}
	}

	// Pod Security Policy (PSP)
	recResult, recErr = r.createOrUpdatePodSecurityPolicy(instance)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}

	// // ConfigMap (RuleTable)
	// recResult, recErr = r.createOrUpdateRuleTableConfigMap(instance)
	// if recErr != nil || recResult.Requeue {
	// 	return recResult, recErr
	// }

	// // ConfigMap (IgnoreSATable)
	// recResult, recErr = r.createOrUpdateIgnoreRuleTableConfigMap(instance)
	// if recErr != nil || recResult.Requeue {
	// 	return recResult, recErr
	// }

	// // ConfigMap (ForceCheckTable)
	// recResult, recErr = r.createOrUpdateForceCheckRuleTableConfigMap(instance)
	// if recErr != nil || recResult.Requeue {
	// 	return recResult, recErr
	// }

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

func (r *IntegrityVerifierReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&apisv1alpha1.IntegrityVerifier{}).
		Owns(&apisv1alpha1.IntegrityVerifier{}).
		Complete(r)
}
