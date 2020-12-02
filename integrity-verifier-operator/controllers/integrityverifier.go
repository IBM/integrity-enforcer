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
	"reflect"
	"time"

	apiv1alpha1 "github.com/IBM/integrity-enforcer/integrity-verifier-operator/api/v1alpha1"
	res "github.com/IBM/integrity-enforcer/integrity-verifier-operator/resources"
	rsp "github.com/IBM/integrity-enforcer/verifier/pkg/apis/resourcesigningprofile/v1alpha1"
	admv1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"

	cert "github.com/IBM/integrity-enforcer/integrity-verifier-operator/cert"

	spol "github.com/IBM/integrity-enforcer/verifier/pkg/apis/signpolicy/v1alpha1"
	ec "github.com/IBM/integrity-enforcer/verifier/pkg/apis/verifierconfig/v1alpha1"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

/**********************************************

				Namespace

***********************************************/

func (r *IntegrityVerifierReconciler) attachLabelToNamespace(instance *apiv1alpha1.IntegrityVerifier, expected *v1.Namespace) (ctrl.Result, error) {
	ctx := context.Background()

	found := &v1.Namespace{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"Namespace.Name", expected.Name)

	// If CRD does not exist, create it and requeue
	err := r.Get(ctx, types.NamespacedName{Name: expected.Name, Namespace: ""}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info(fmt.Sprintf("Skip reconcile: namespace \"%s\" does not exist, skip to attach IV label to this namespace.", expected.Name))
		return ctrl.Result{}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	} else {
		if !reflect.DeepEqual(expected.ObjectMeta.Labels, found.ObjectMeta.Labels) {
			labels := expected.ObjectMeta.Labels
			expected.ObjectMeta = found.ObjectMeta
			expected.ObjectMeta.Labels = labels
			err = r.Update(ctx, expected)
			if err != nil {
				reqLogger.Error(err, "Failed to update the resource")
				return ctrl.Result{}, err
			}
		}
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil

}

/**********************************************

				CRD

***********************************************/

func (r *IntegrityVerifierReconciler) createOrUpdateCRD(instance *apiv1alpha1.IntegrityVerifier, expected *extv1.CustomResourceDefinition) (ctrl.Result, error) {
	ctx := context.Background()

	found := &extv1.CustomResourceDefinition{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"CRD.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return ctrl.Result{}, err
	}

	// If CRD does not exist, create it and requeue
	err = r.Get(ctx, types.NamespacedName{Name: expected.Name, Namespace: ""}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.Create(ctx, expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return ctrl.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return ctrl.Result{}, err
		}
		// Created successfully - return and requeue
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	} else {
		if !reflect.DeepEqual(expected.Spec, found.Spec) {
			expected.ObjectMeta = found.ObjectMeta
			err = r.Update(ctx, expected)
			if err != nil {
				reqLogger.Error(err, "Failed to update the resource")
				return ctrl.Result{}, err
			}
		}
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil

}

func (r *IntegrityVerifierReconciler) createOrUpdateVerifierConfigCRD(
	instance *apiv1alpha1.IntegrityVerifier) (ctrl.Result, error) {
	expected := res.BuildVerifierConfigCRD(instance)
	return r.createOrUpdateCRD(instance, expected)
}

func (r *IntegrityVerifierReconciler) createOrUpdateSignPolicyCRD(
	instance *apiv1alpha1.IntegrityVerifier) (ctrl.Result, error) {
	expected := res.BuildSignPolicyCRD(instance)
	return r.createOrUpdateCRD(instance, expected)
}
func (r *IntegrityVerifierReconciler) createOrUpdateResourceSignatureCRD(
	instance *apiv1alpha1.IntegrityVerifier) (ctrl.Result, error) {
	expected := res.BuildResourceSignatureCRD(instance)
	return r.createOrUpdateCRD(instance, expected)
}

func (r *IntegrityVerifierReconciler) createOrUpdateHelmReleaseMetadataCRD(
	instance *apiv1alpha1.IntegrityVerifier) (ctrl.Result, error) {
	expected := res.BuildHelmReleaseMetadataCRD(instance)
	return r.createOrUpdateCRD(instance, expected)
}

func (r *IntegrityVerifierReconciler) createOrUpdateResourceSigningProfileCRD(
	instance *apiv1alpha1.IntegrityVerifier) (ctrl.Result, error) {
	expected := res.BuildResourceSigningProfileCRD(instance)
	return r.createOrUpdateCRD(instance, expected)
}

/**********************************************

				CR

***********************************************/

func (r *IntegrityVerifierReconciler) createOrUpdateVerifierConfigCR(instance *apiv1alpha1.IntegrityVerifier) (ctrl.Result, error) {
	ctx := context.Background()

	expected := res.BuildVerifierConfigForIV(instance, r.Scheme)
	found := &ec.VerifierConfig{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"VerifierConfig.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return ctrl.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.Get(ctx, types.NamespacedName{Name: expected.Name, Namespace: instance.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.Create(ctx, expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return ctrl.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return ctrl.Result{}, err
		}
		// Created successfully - return and requeue
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	} else {
		if !reflect.DeepEqual(expected.Spec, found.Spec) {
			expected.ObjectMeta = found.ObjectMeta
			err = r.Update(ctx, expected)
			if err != nil {
				reqLogger.Error(err, "Failed to update the resource")
				return ctrl.Result{}, err
			}
		}
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil

}

func (r *IntegrityVerifierReconciler) createOrUpdateSignPolicyCR(instance *apiv1alpha1.IntegrityVerifier) (ctrl.Result, error) {
	ctx := context.Background()
	found := &spol.SignPolicy{}
	expected := res.BuildSignEnforcePolicyForIV(instance)

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"SignPolicy.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return ctrl.Result{}, err
	}

	// If default rpp does not exist, create it and requeue
	err = r.Get(ctx, types.NamespacedName{Name: expected.Name, Namespace: instance.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.Create(ctx, expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return ctrl.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return ctrl.Result{}, err
		}
		// Created successfully - return and requeue
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	} else {
		if !reflect.DeepEqual(expected.Spec, found.Spec) {
			expected.ObjectMeta = found.ObjectMeta
			err = r.Update(ctx, expected)
			if err != nil {
				reqLogger.Error(err, "Failed to update the resource")
				return ctrl.Result{}, err
			}
		}
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil

}

func (r *IntegrityVerifierReconciler) createOrUpdateResourceSigningProfileCR(instance *apiv1alpha1.IntegrityVerifier, prof *apiv1alpha1.ProfileConfig) (ctrl.Result, error) {
	ctx := context.Background()
	found := &rsp.ResourceSigningProfile{}
	expected := res.BuildResourceSigningProfileForIV(instance, prof)
	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"ResourceSigningProfile.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return ctrl.Result{}, err
	}

	// If RSP does not exist, create it and requeue
	err = r.Get(ctx, types.NamespacedName{Name: expected.Name, Namespace: instance.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.Create(ctx, expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return ctrl.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return ctrl.Result{}, err
		}
		// Created successfully - return and requeue
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	} else {
		if !reflect.DeepEqual(expected.Spec, found.Spec) {
			expected.ObjectMeta = found.ObjectMeta
			err = r.Update(ctx, expected)
			if err != nil {
				reqLogger.Error(err, "Failed to update the resource")
				return ctrl.Result{}, err
			}
		}
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil

}

/**********************************************

				Role

***********************************************/

func (r *IntegrityVerifierReconciler) createOrUpdateServiceAccount(instance *apiv1alpha1.IntegrityVerifier) (ctrl.Result, error) {
	ctx := context.Background()
	expected := res.BuildServiceAccountForIV(instance)
	found := &corev1.ServiceAccount{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"ServiceAccount.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return ctrl.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.Get(ctx, types.NamespacedName{Name: expected.Name, Namespace: instance.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.Create(ctx, expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return ctrl.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return ctrl.Result{}, err
		}
		// Created successfully - return and requeue
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil

}

func (r *IntegrityVerifierReconciler) createOrUpdateClusterRole(instance *apiv1alpha1.IntegrityVerifier, expected *rbacv1.ClusterRole) (ctrl.Result, error) {
	ctx := context.Background()
	found := &rbacv1.ClusterRole{}

	reqLogger := r.Log.WithValues(
		"ClusterRole.Namespace", instance.Namespace,
		"Instance.Name", instance.Name,
		"ClusterRole.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return ctrl.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.Get(ctx, types.NamespacedName{Name: expected.Name}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.Create(ctx, expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return ctrl.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return ctrl.Result{}, err
		}
		// Created successfully - return and requeue
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil

}

func (r *IntegrityVerifierReconciler) createOrUpdateClusterRoleBinding(instance *apiv1alpha1.IntegrityVerifier, expected *rbacv1.ClusterRoleBinding) (ctrl.Result, error) {
	ctx := context.Background()
	found := &rbacv1.ClusterRoleBinding{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"RoleBinding.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return ctrl.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.Get(ctx, types.NamespacedName{Name: expected.Name}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.Create(ctx, expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return ctrl.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return ctrl.Result{}, err
		}
		// Created successfully - return and requeue
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil

}

func (r *IntegrityVerifierReconciler) createOrUpdateRole(instance *apiv1alpha1.IntegrityVerifier, expected *rbacv1.Role) (ctrl.Result, error) {
	ctx := context.Background()
	found := &rbacv1.Role{}

	reqLogger := r.Log.WithValues(
		"Role.Namespace", instance.Namespace,
		"Instance.Name", instance.Name,
		"Role.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return ctrl.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.Get(ctx, types.NamespacedName{Namespace: instance.Namespace, Name: expected.Name}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.Create(ctx, expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return ctrl.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return ctrl.Result{}, err
		}
		// Created successfully - return and requeue
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil

}

func (r *IntegrityVerifierReconciler) createOrUpdateRoleBinding(instance *apiv1alpha1.IntegrityVerifier, expected *rbacv1.RoleBinding) (ctrl.Result, error) {
	ctx := context.Background()
	found := &rbacv1.RoleBinding{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"RoleBinding.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return ctrl.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.Get(ctx, types.NamespacedName{Namespace: instance.Namespace, Name: expected.Name}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.Create(ctx, expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return ctrl.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return ctrl.Result{}, err
		}
		// Created successfully - return and requeue
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil

}

// iv-admin
func (r *IntegrityVerifierReconciler) createOrUpdateClusterRoleBindingForIVAdmin(
	instance *apiv1alpha1.IntegrityVerifier) (ctrl.Result, error) {
	expected := res.BuildClusterRoleBindingForIVAdmin(instance)
	return r.createOrUpdateClusterRoleBinding(instance, expected)
}

func (r *IntegrityVerifierReconciler) createOrUpdateRoleBindingForIVAdmin(
	instance *apiv1alpha1.IntegrityVerifier) (ctrl.Result, error) {
	expected := res.BuildRoleBindingForIVAdmin(instance)
	return r.createOrUpdateRoleBinding(instance, expected)
}

func (r *IntegrityVerifierReconciler) createOrUpdateRoleForIVAdmin(
	instance *apiv1alpha1.IntegrityVerifier) (ctrl.Result, error) {
	expected := res.BuildRoleForIVAdmin(instance)
	return r.createOrUpdateRole(instance, expected)
}

func (r *IntegrityVerifierReconciler) createOrUpdateClusterRoleForIVAdmin(
	instance *apiv1alpha1.IntegrityVerifier) (ctrl.Result, error) {
	expected := res.BuildClusterRoleForIVAdmin(instance)
	return r.createOrUpdateClusterRole(instance, expected)
}

// for ie
func (r *IntegrityVerifierReconciler) createOrUpdateClusterRoleBindingForIV(
	instance *apiv1alpha1.IntegrityVerifier) (ctrl.Result, error) {
	expected := res.BuildClusterRoleBindingForIV(instance)
	return r.createOrUpdateClusterRoleBinding(instance, expected)
}

func (r *IntegrityVerifierReconciler) createOrUpdateRoleBindingForIV(
	instance *apiv1alpha1.IntegrityVerifier) (ctrl.Result, error) {
	expected := res.BuildRoleBindingForIV(instance)
	return r.createOrUpdateRoleBinding(instance, expected)
}

func (r *IntegrityVerifierReconciler) createOrUpdateRoleForIV(
	instance *apiv1alpha1.IntegrityVerifier) (ctrl.Result, error) {
	expected := res.BuildRoleForIV(instance)
	return r.createOrUpdateRole(instance, expected)
}

func (r *IntegrityVerifierReconciler) createOrUpdateClusterRoleForIV(
	instance *apiv1alpha1.IntegrityVerifier) (ctrl.Result, error) {
	expected := res.BuildClusterRoleForIV(instance)
	return r.createOrUpdateClusterRole(instance, expected)
}

func (r *IntegrityVerifierReconciler) createOrUpdatePodSecurityPolicy(instance *apiv1alpha1.IntegrityVerifier) (ctrl.Result, error) {
	ctx := context.Background()
	expected := res.BuildPodSecurityPolicy(instance)
	found := &policyv1.PodSecurityPolicy{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"PodSecurityPolicy.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return ctrl.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.Get(ctx, types.NamespacedName{Name: expected.Name}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.Create(ctx, expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return ctrl.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return ctrl.Result{}, err
		}
		// Created successfully - return and requeue
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil

}

/**********************************************

				Secret

***********************************************/

func (r *IntegrityVerifierReconciler) isKeyRingReady(instance *apiv1alpha1.IntegrityVerifier) (bool, string) {
	ctx := context.Background()
	found := &corev1.Secret{}
	okCount := 0
	nonReadyKey := ""
	for _, keyConf := range instance.Spec.KeyRings {
		if keyConf.CreateIfNotExist {
			okCount += 1
			continue
		}
		err := r.Get(ctx, types.NamespacedName{Name: keyConf.Name, Namespace: instance.Namespace}, found)
		if err == nil {
			okCount += 1
		} else {
			nonReadyKey = keyConf.Name
			break
		}
	}
	ok := (okCount == len(instance.Spec.KeyRings))
	return ok, nonReadyKey
}

func (r *IntegrityVerifierReconciler) createOrUpdateSecret(instance *apiv1alpha1.IntegrityVerifier, expected *corev1.Secret) (ctrl.Result, error) {
	ctx := context.Background()
	found := &corev1.Secret{}

	reqLogger := r.Log.WithValues(
		"Secret.Namespace", instance.Namespace,
		"Instance.Name", instance.Name,
		"Secret.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return ctrl.Result{}, err
	}

	// If CRD does not exist, create it and requeue
	err = r.Get(ctx, types.NamespacedName{Name: expected.Name, Namespace: instance.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {

		reqLogger.Info("Creating a new resource")
		err = r.Create(ctx, expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return ctrl.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return ctrl.Result{}, err
		}
		// Created successfully - return and requeue
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil

}

func (r *IntegrityVerifierReconciler) createOrUpdateCertSecret(instance *apiv1alpha1.IntegrityVerifier, expected *corev1.Secret) (ctrl.Result, error) {
	ctx := context.Background()
	found := &corev1.Secret{}

	reqLogger := r.Log.WithValues(
		"Secret.Namespace", instance.Namespace,
		"Instance.Name", instance.Name,
		"Secret.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return ctrl.Result{}, err
	}

	// If CRD does not exist, create it and requeue
	err = r.Get(ctx, types.NamespacedName{Name: expected.Name, Namespace: instance.Namespace}, found)

	expected = addCertValues(instance, expected)

	if err != nil && errors.IsNotFound(err) {

		reqLogger.Info("Creating a new resource")
		err = r.Create(ctx, expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return ctrl.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return ctrl.Result{}, err
		}
		// Created successfully - return and requeue
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil

}

func addCertValues(instance *apiv1alpha1.IntegrityVerifier, expected *corev1.Secret) *corev1.Secret {
	reqLogger := log.WithValues(
		"Secret.Namespace", instance.Namespace,
		"Instance.Name", instance.Name,
		"Secret.Name", expected.Name)

	// generate and put certsß
	ca, tlsKey, tlsCert, err := cert.GenerateCert(instance.GetWebhookServiceName(), instance.Namespace)
	if err != nil {
		reqLogger.Error(err, "Failed to generate certs")
	}

	_, ok_tc := expected.Data["tls.crt"]
	_, ok_tk := expected.Data["tls.key"]
	_, ok_ca := expected.Data["ca.crt"]
	if ok_ca && ok_tc && ok_tk {
		expected.Data["tls.crt"] = tlsCert
		expected.Data["tls.key"] = tlsKey
		expected.Data["ca.crt"] = ca
	}
	return expected
}

func (r *IntegrityVerifierReconciler) createOrUpdateRegKeySecret(
	instance *apiv1alpha1.IntegrityVerifier) (ctrl.Result, error) {
	expected := res.BuildRegKeySecretForCR(instance)
	return r.createOrUpdateSecret(instance, expected)
}

func (r *IntegrityVerifierReconciler) createOrUpdateTlsSecret(
	instance *apiv1alpha1.IntegrityVerifier) (ctrl.Result, error) {
	expected := res.BuildTlsSecretForIV(instance)
	return r.createOrUpdateCertSecret(instance, expected)
}

/**********************************************

				ConfigMap

***********************************************/

func (r *IntegrityVerifierReconciler) createOrUpdateConfigMap(instance *apiv1alpha1.IntegrityVerifier, expected *v1.ConfigMap) (ctrl.Result, error) {
	ctx := context.Background()
	found := &corev1.ConfigMap{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"ConfigMap.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return ctrl.Result{}, err
	}

	// If ConfigMap does not exist, create it and requeue
	err = r.Get(ctx, types.NamespacedName{Name: expected.Name, Namespace: instance.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.Create(ctx, expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return ctrl.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return ctrl.Result{}, err
		}
		// Created successfully - return and requeue
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil
}

func (r *IntegrityVerifierReconciler) createOrUpdateRuleTableConfigMap(instance *apiv1alpha1.IntegrityVerifier) (ctrl.Result, error) {
	expected := res.BuildRuleTableLockConfigMapForCR(instance)
	return r.createOrUpdateConfigMap(instance, expected)
}

func (r *IntegrityVerifierReconciler) createOrUpdateIgnoreRuleTableConfigMap(instance *apiv1alpha1.IntegrityVerifier) (ctrl.Result, error) {
	expected := res.BuildIgnoreRuleTableLockConfigMapForCR(instance)
	return r.createOrUpdateConfigMap(instance, expected)
}

func (r *IntegrityVerifierReconciler) createOrUpdateForceCheckRuleTableConfigMap(instance *apiv1alpha1.IntegrityVerifier) (ctrl.Result, error) {
	expected := res.BuildForceCheckRuleTableLockConfigMapForCR(instance)
	return r.createOrUpdateConfigMap(instance, expected)
}

/**********************************************

				Deployment

***********************************************/

func (r *IntegrityVerifierReconciler) createOrUpdateDeployment(instance *apiv1alpha1.IntegrityVerifier, expected *appsv1.Deployment) (ctrl.Result, error) {
	ctx := context.Background()
	found := &appsv1.Deployment{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"Deployment.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return ctrl.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.Get(ctx, types.NamespacedName{Name: expected.Name, Namespace: instance.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.Create(ctx, expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return ctrl.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return ctrl.Result{}, err
		}
		// Created successfully - return and requeue
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	} else if !res.EqualDeployments(expected, found) {
		// If spec is incorrect, update it and requeue
		found.ObjectMeta.Labels = expected.ObjectMeta.Labels
		found.Spec = expected.Spec
		err = r.Update(ctx, found)
		if err != nil {
			reqLogger.Error(err, "Failed to update Deployment", "Namespace", instance.Namespace, "Name", found.Name)
			return ctrl.Result{}, err
		}
		reqLogger.Info("Updating IntegrityVerifier Controller Deployment", "Deployment.Name", found.Name)
		// Spec updated - return and requeue
		return ctrl.Result{Requeue: true}, nil
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil

}

func (r *IntegrityVerifierReconciler) createOrUpdateWebhookDeployment(instance *apiv1alpha1.IntegrityVerifier) (ctrl.Result, error) {
	expected := res.BuildDeploymentForCR(instance)
	return r.createOrUpdateDeployment(instance, expected)
}

/**********************************************

				Service

***********************************************/

func (r *IntegrityVerifierReconciler) createOrUpdateService(instance *apiv1alpha1.IntegrityVerifier, expected *corev1.Service) (ctrl.Result, error) {
	ctx := context.Background()
	found := &corev1.Service{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"Instance.Spec.ServiceName", instance.GetWebhookServiceName(),
		"Service.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return ctrl.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.Get(ctx, types.NamespacedName{Name: expected.Name, Namespace: instance.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.Create(ctx, expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return ctrl.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return ctrl.Result{}, err
		}
		// Created successfully - return and requeue
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil
}

func (r *IntegrityVerifierReconciler) createOrUpdateWebhookService(instance *apiv1alpha1.IntegrityVerifier) (ctrl.Result, error) {
	expected := res.BuildServiceForCR(instance)
	return r.createOrUpdateService(instance, expected)
}

/**********************************************

				Webhook

***********************************************/

func (r *IntegrityVerifierReconciler) createOrUpdateWebhook(instance *apiv1alpha1.IntegrityVerifier) (ctrl.Result, error) {
	ctx := context.Background()
	expected := res.BuildMutatingWebhookConfigurationForIV(instance)
	found := &admv1.MutatingWebhookConfiguration{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"MutatingWebhookConfiguration.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return ctrl.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.Get(ctx, types.NamespacedName{Name: expected.Name}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		// locad cabundle
		secret := &corev1.Secret{}
		err = r.Get(ctx, types.NamespacedName{Name: instance.GetWebhookServerTlsSecretName(), Namespace: instance.Namespace}, secret)
		if err != nil {
			reqLogger.Error(err, "Fail to load CABundle from Secret")
		}
		cabundle, ok := secret.Data["ca.crt"]
		if ok {
			expected.Webhooks[0].ClientConfig.CABundle = cabundle
		}

		err = r.Create(ctx, expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return ctrl.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return ctrl.Result{}, err
		}
		// Created successfully - return and requeue

		reqLogger.Info("Webhook has been created.", "Name", instance.Name)
		evtName := fmt.Sprintf("iv-webhook-reconciled")
		_ = r.createOrUpdateWebhookEvent(instance, evtName, expected.Name)

		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil

}

// delete webhookconfiguration
func (r *IntegrityVerifierReconciler) deleteWebhook(instance *apiv1alpha1.IntegrityVerifier) (ctrl.Result, error) {
	ctx := context.Background()
	expected := res.BuildMutatingWebhookConfigurationForIV(instance)
	found := &admv1.MutatingWebhookConfiguration{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"MutatingWebhookConfiguration.Name", expected.Name)

	err := r.Get(ctx, types.NamespacedName{Name: expected.Name}, found)

	if err == nil {
		reqLogger.Info("Deleting the IV webhook")
		err = r.Delete(ctx, found)
		if err != nil {
			reqLogger.Error(err, "Failed to delete the IV Webhook")
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if errors.IsNotFound(err) {
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else {
		return ctrl.Result{}, err
	}
}

// wait function
func (r *IntegrityVerifierReconciler) isDeploymentAvailable(instance *apiv1alpha1.IntegrityVerifier) bool {
	ctx := context.Background()
	found := &appsv1.Deployment{}

	// If Deployment does not exist, return false
	err := r.Get(ctx, types.NamespacedName{Name: instance.Name, Namespace: instance.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		return false
	} else if err != nil {
		return false
	}

	// return true only if deployment is available
	if found.Status.AvailableReplicas > 0 {
		return true
	}

	return false
}

func (r *IntegrityVerifierReconciler) createOrUpdateWebhookEvent(instance *apiv1alpha1.IntegrityVerifier, evtName, webhookName string) error {
	ctx := context.Background()
	evtNamespace := instance.Namespace
	involvedObject := v1.ObjectReference{
		Namespace:  evtNamespace,
		APIVersion: instance.APIVersion,
		Kind:       instance.Kind,
		Name:       instance.Name,
	}
	now := time.Now()
	evtSourceName := "IntegrityVerifier"
	msg := fmt.Sprintf("IntegrityVerifier reconciled MutatingWebhookConfiguration \"%s\"", webhookName)
	expected := &v1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      evtName,
			Namespace: evtNamespace,
		},
		InvolvedObject:      involvedObject,
		Type:                evtSourceName,
		Source:              v1.EventSource{Component: evtSourceName},
		ReportingController: evtSourceName,
		ReportingInstance:   evtName,
		Action:              evtName,
		FirstTimestamp:      metav1.NewTime(now),
		LastTimestamp:       metav1.NewTime(now),
		EventTime:           metav1.NewMicroTime(now),
		Message:             msg,
		Reason:              msg,
	}
	found := &v1.Event{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"Event.Name", expected.Name)

	// If Event does not exist, create it and requeue
	err := r.Get(ctx, types.NamespacedName{Name: expected.Name, Namespace: expected.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new event")
		err = r.Create(ctx, expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip creating event: resource already exists")
			return nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new event")
			return err
		}
		// Created successfully - return and requeue
		return nil
	} else if err != nil {
		return err
	} else {
		// Update Event
		found.Count = found.Count + 1
		found.EventTime = metav1.NewMicroTime(now)
		found.LastTimestamp = metav1.NewTime(now)
		found.Message = msg
		found.Reason = msg
		found.ReportingController = evtSourceName
		found.ReportingInstance = evtName

		err = r.Update(ctx, found)
		if err != nil {
			reqLogger.Error(err, "Failed to update Event", "Namespace", instance.Namespace, "Name", found.Name)
			return err
		}
		reqLogger.Info("Updated Event", "Deployment.Name", found.Name)
		// Spec updated - return and requeue
		return nil
	}
}
