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

	rsp "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/resourcesigningprofile/v1alpha1"
	apiv1alpha1 "github.com/IBM/integrity-enforcer/integrity-enforcer-operator/api/v1alpha1"
	res "github.com/IBM/integrity-enforcer/integrity-enforcer-operator/resources"
	scc "github.com/openshift/api/security/v1"
	admv1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cert "github.com/IBM/integrity-enforcer/integrity-enforcer-operator/cert"

	ec "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/enforcerconfig/v1alpha1"
	spol "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/signpolicy/v1alpha1"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

/**********************************************

				Namespace

***********************************************/

const ieTargetNamespaceLabelKey = "integrity-enforced"
const ieTargetNamespaceLabelValue = "true"

func (r *IntegrityEnforcerReconciler) attachLabelToNamespace(instance *apiv1alpha1.IntegrityEnforcer, expected *v1.Namespace) (ctrl.Result, error) {
	ctx := context.Background()

	found := &v1.Namespace{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"Namespace.Name", expected.Name)

	// If CRD does not exist, create it and requeue
	err := r.Get(ctx, types.NamespacedName{Name: expected.Name, Namespace: ""}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info(fmt.Sprintf("Skip reconcile: namespace \"%s\" does not exist, skip to attach IE label to this namespace.", expected.Name))
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

func (r *IntegrityEnforcerReconciler) attachLabelToNamespacesInCR(
	instance *apiv1alpha1.IntegrityEnforcer) (ctrl.Result, error) {
	for _, nsName := range instance.Spec.LabeledNamespaces {
		expected := &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: nsName,
				Labels: map[string]string{
					ieTargetNamespaceLabelKey: ieTargetNamespaceLabelValue,
				},
			},
		}
		res, err := r.attachLabelToNamespace(instance, expected)
		if err != nil {
			return res, err
		}
	}
	return ctrl.Result{}, nil
}

/**********************************************

				CRD

***********************************************/

func (r *IntegrityEnforcerReconciler) createOrUpdateCRD(instance *apiv1alpha1.IntegrityEnforcer, expected *extv1.CustomResourceDefinition) (ctrl.Result, error) {
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

func (r *IntegrityEnforcerReconciler) createOrUpdateEnforcerConfigCRD(
	instance *apiv1alpha1.IntegrityEnforcer) (ctrl.Result, error) {
	expected := res.BuildEnforcerConfigCRD(instance)
	return r.createOrUpdateCRD(instance, expected)
}

func (r *IntegrityEnforcerReconciler) createOrUpdateSignPolicyCRD(
	instance *apiv1alpha1.IntegrityEnforcer) (ctrl.Result, error) {
	expected := res.BuildSignPolicyCRD(instance)
	return r.createOrUpdateCRD(instance, expected)
}
func (r *IntegrityEnforcerReconciler) createOrUpdateResourceSignatureCRD(
	instance *apiv1alpha1.IntegrityEnforcer) (ctrl.Result, error) {
	expected := res.BuildResourceSignatureCRD(instance)
	return r.createOrUpdateCRD(instance, expected)
}

func (r *IntegrityEnforcerReconciler) createOrUpdateHelmReleaseMetadataCRD(
	instance *apiv1alpha1.IntegrityEnforcer) (ctrl.Result, error) {
	expected := res.BuildHelmReleaseMetadataCRD(instance)
	return r.createOrUpdateCRD(instance, expected)
}

func (r *IntegrityEnforcerReconciler) createOrUpdateResourceSigningProfileCRD(
	instance *apiv1alpha1.IntegrityEnforcer) (ctrl.Result, error) {
	expected := res.BuildResourceSigningProfileCRD(instance)
	return r.createOrUpdateCRD(instance, expected)
}

/**********************************************

				CR

***********************************************/

func (r *IntegrityEnforcerReconciler) createOrUpdateEnforcerConfigCR(instance *apiv1alpha1.IntegrityEnforcer) (ctrl.Result, error) {
	ctx := context.Background()

	expected := res.BuildEnforcerConfigForIE(instance, r.Scheme)
	found := &ec.EnforcerConfig{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"EnforcerConfig.Name", expected.Name)

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

func (r *IntegrityEnforcerReconciler) createOrUpdateSignPolicyCR(instance *apiv1alpha1.IntegrityEnforcer) (ctrl.Result, error) {
	ctx := context.Background()
	found := &spol.SignPolicy{}
	expected := res.BuildSignEnforcePolicyForIE(instance)

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

func (r *IntegrityEnforcerReconciler) createOrUpdateResourceSigningProfileCR(instance *apiv1alpha1.IntegrityEnforcer, prof *apiv1alpha1.ProfileConfig) (ctrl.Result, error) {
	ctx := context.Background()
	found := &rsp.ResourceSigningProfile{}
	expected := res.BuildResourceSigningProfileForIE(instance, prof)

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

func (r *IntegrityEnforcerReconciler) createOrUpdateSCC(instance *apiv1alpha1.IntegrityEnforcer) (ctrl.Result, error) {
	ctx := context.Background()
	expected := res.BuildSecurityContextConstraints(instance)
	found := &scc.SecurityContextConstraints{}

	found.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "security.openshift.io",
		Kind:    "SecurityContextConstraints",
		Version: "v1",
	})

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"SecurityContextConstraints.Name", expected.Name)

	// // Set CR instance as the owner and controller
	// err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
	// if err != nil {
	// 	reqLogger.Error(err, "Failed to define expected resource")
	// 	return ctrl.Result{}, err
	// }

	err := r.Get(ctx, types.NamespacedName{Name: expected.Name, Namespace: ""}, found)

	if err != nil && errors.IsNotFound(err) {
		// Define a new ClusterRole
		reqLogger.Info("Creating a new SCC", "SCC.Name", expected)
		err = r.Create(ctx, expected)
		if err != nil {
			reqLogger.Error(err, "Failed to create new SCC", "SCC.Name", expected)
			return ctrl.Result{}, err
		}
		// ClusterRole created successfully - return and requeue
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		reqLogger.Error(err, "Failed to get SCC")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *IntegrityEnforcerReconciler) createOrUpdateServiceAccount(instance *apiv1alpha1.IntegrityEnforcer) (ctrl.Result, error) {
	ctx := context.Background()
	expected := res.BuildServiceAccountForIE(instance)
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

func (r *IntegrityEnforcerReconciler) createOrUpdateClusterRole(instance *apiv1alpha1.IntegrityEnforcer, expected *rbacv1.ClusterRole) (ctrl.Result, error) {
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

func (r *IntegrityEnforcerReconciler) createOrUpdateClusterRoleBinding(instance *apiv1alpha1.IntegrityEnforcer, expected *rbacv1.ClusterRoleBinding) (ctrl.Result, error) {
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

func (r *IntegrityEnforcerReconciler) createOrUpdateRole(instance *apiv1alpha1.IntegrityEnforcer, expected *rbacv1.Role) (ctrl.Result, error) {
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

func (r *IntegrityEnforcerReconciler) createOrUpdateRoleBinding(instance *apiv1alpha1.IntegrityEnforcer, expected *rbacv1.RoleBinding) (ctrl.Result, error) {
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

// ie-admin
func (r *IntegrityEnforcerReconciler) createOrUpdateClusterRoleBindingForIEAdmin(
	instance *apiv1alpha1.IntegrityEnforcer) (ctrl.Result, error) {
	expected := res.BuildClusterRoleBindingForIEAdmin(instance)
	return r.createOrUpdateClusterRoleBinding(instance, expected)
}

func (r *IntegrityEnforcerReconciler) createOrUpdateRoleBindingForIEAdmin(
	instance *apiv1alpha1.IntegrityEnforcer) (ctrl.Result, error) {
	expected := res.BuildRoleBindingForIEAdmin(instance)
	return r.createOrUpdateRoleBinding(instance, expected)
}

func (r *IntegrityEnforcerReconciler) createOrUpdateRoleForIEAdmin(
	instance *apiv1alpha1.IntegrityEnforcer) (ctrl.Result, error) {
	expected := res.BuildRoleForIEAdmin(instance)
	return r.createOrUpdateRole(instance, expected)
}

func (r *IntegrityEnforcerReconciler) createOrUpdateClusterRoleForIEAdmin(
	instance *apiv1alpha1.IntegrityEnforcer) (ctrl.Result, error) {
	expected := res.BuildClusterRoleForIEAdmin(instance)
	return r.createOrUpdateClusterRole(instance, expected)
}

// for ie
func (r *IntegrityEnforcerReconciler) createOrUpdateClusterRoleBindingForIE(
	instance *apiv1alpha1.IntegrityEnforcer) (ctrl.Result, error) {
	expected := res.BuildClusterRoleBindingForIE(instance)
	return r.createOrUpdateClusterRoleBinding(instance, expected)
}

func (r *IntegrityEnforcerReconciler) createOrUpdateRoleBindingForIE(
	instance *apiv1alpha1.IntegrityEnforcer) (ctrl.Result, error) {
	expected := res.BuildRoleBindingForIE(instance)
	return r.createOrUpdateRoleBinding(instance, expected)
}

func (r *IntegrityEnforcerReconciler) createOrUpdateRoleForIE(
	instance *apiv1alpha1.IntegrityEnforcer) (ctrl.Result, error) {
	expected := res.BuildRoleForIE(instance)
	return r.createOrUpdateRole(instance, expected)
}

func (r *IntegrityEnforcerReconciler) createOrUpdateClusterRoleForIE(
	instance *apiv1alpha1.IntegrityEnforcer) (ctrl.Result, error) {
	expected := res.BuildClusterRoleForIE(instance)
	return r.createOrUpdateClusterRole(instance, expected)
}

func (r *IntegrityEnforcerReconciler) createOrUpdatePodSecurityPolicy(instance *apiv1alpha1.IntegrityEnforcer) (ctrl.Result, error) {
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

func (r *IntegrityEnforcerReconciler) isKeyRingReady(instance *apiv1alpha1.IntegrityEnforcer) (bool, string) {
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

func (r *IntegrityEnforcerReconciler) createOrUpdateSecret(instance *apiv1alpha1.IntegrityEnforcer, expected *corev1.Secret) (ctrl.Result, error) {
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

func (r *IntegrityEnforcerReconciler) createOrUpdateCertSecret(instance *apiv1alpha1.IntegrityEnforcer, expected *corev1.Secret) (ctrl.Result, error) {
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

func addCertValues(instance *apiv1alpha1.IntegrityEnforcer, expected *corev1.Secret) *corev1.Secret {
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

func (r *IntegrityEnforcerReconciler) createOrUpdateRegKeySecret(
	instance *apiv1alpha1.IntegrityEnforcer) (ctrl.Result, error) {
	expected := res.BuildRegKeySecretForCR(instance)
	return r.createOrUpdateSecret(instance, expected)
}

func (r *IntegrityEnforcerReconciler) createOrUpdateTlsSecret(
	instance *apiv1alpha1.IntegrityEnforcer) (ctrl.Result, error) {
	expected := res.BuildTlsSecretForIE(instance)
	return r.createOrUpdateCertSecret(instance, expected)
}

/**********************************************

				ConfigMap

***********************************************/

func (r *IntegrityEnforcerReconciler) createOrUpdateConfigMap(instance *apiv1alpha1.IntegrityEnforcer, expected *v1.ConfigMap) (ctrl.Result, error) {
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

func (r *IntegrityEnforcerReconciler) createOrUpdateRuleTableConfigMap(instance *apiv1alpha1.IntegrityEnforcer) (ctrl.Result, error) {
	expected := res.BuildRuleTableLockConfigMapForCR(instance)
	return r.createOrUpdateConfigMap(instance, expected)
}

func (r *IntegrityEnforcerReconciler) createOrUpdateIgnoreRuleTableConfigMap(instance *apiv1alpha1.IntegrityEnforcer) (ctrl.Result, error) {
	expected := res.BuildIgnoreRuleTableLockConfigMapForCR(instance)
	return r.createOrUpdateConfigMap(instance, expected)
}

func (r *IntegrityEnforcerReconciler) createOrUpdateForceCheckRuleTableConfigMap(instance *apiv1alpha1.IntegrityEnforcer) (ctrl.Result, error) {
	expected := res.BuildForceCheckRuleTableLockConfigMapForCR(instance)
	return r.createOrUpdateConfigMap(instance, expected)
}

/**********************************************

				Deployment

***********************************************/

func (r *IntegrityEnforcerReconciler) createOrUpdateDeployment(instance *apiv1alpha1.IntegrityEnforcer, expected *appsv1.Deployment) (ctrl.Result, error) {
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
		reqLogger.Info("Updating IntegrityEnforcer Controller Deployment", "Deployment.Name", found.Name)
		// Spec updated - return and requeue
		return ctrl.Result{Requeue: true}, nil
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil

}

func (r *IntegrityEnforcerReconciler) createOrUpdateWebhookDeployment(instance *apiv1alpha1.IntegrityEnforcer) (ctrl.Result, error) {
	expected := res.BuildDeploymentForCR(instance)
	return r.createOrUpdateDeployment(instance, expected)
}

/**********************************************

				Service

***********************************************/

func (r *IntegrityEnforcerReconciler) createOrUpdateService(instance *apiv1alpha1.IntegrityEnforcer, expected *corev1.Service) (ctrl.Result, error) {
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

func (r *IntegrityEnforcerReconciler) createOrUpdateWebhookService(instance *apiv1alpha1.IntegrityEnforcer) (ctrl.Result, error) {
	expected := res.BuildServiceForCR(instance)
	return r.createOrUpdateService(instance, expected)
}

/**********************************************

				Webhook

***********************************************/

func (r *IntegrityEnforcerReconciler) createOrUpdateWebhook(instance *apiv1alpha1.IntegrityEnforcer) (ctrl.Result, error) {
	ctx := context.Background()
	expected := res.BuildMutatingWebhookConfigurationForIE(instance)
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
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil

}

// delete webhookconfiguration
func (r *IntegrityEnforcerReconciler) deleteWebhook(instance *apiv1alpha1.IntegrityEnforcer) (ctrl.Result, error) {
	ctx := context.Background()
	expected := res.BuildMutatingWebhookConfigurationForIE(instance)
	found := &admv1.MutatingWebhookConfiguration{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"MutatingWebhookConfiguration.Name", expected.Name)

	err := r.Get(ctx, types.NamespacedName{Name: expected.Name}, found)

	if err == nil {
		reqLogger.Info("Deleting the IE webhook")
		err = r.Delete(ctx, found)
		if err != nil {
			reqLogger.Error(err, "Failed to delete the IE Webhook")
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
func (r *IntegrityEnforcerReconciler) isDeploymentAvailable(instance *apiv1alpha1.IntegrityEnforcer) bool {
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
