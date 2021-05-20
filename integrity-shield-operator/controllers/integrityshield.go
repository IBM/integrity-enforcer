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
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	apiv1alpha1 "github.com/IBM/integrity-enforcer/integrity-shield-operator/api/v1alpha1"
	res "github.com/IBM/integrity-enforcer/integrity-shield-operator/resources"
	rsp "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesigningprofile/v1alpha1"
	common "github.com/IBM/integrity-enforcer/shield/pkg/common"
	admregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	cert "github.com/IBM/integrity-enforcer/integrity-shield-operator/cert"

	ec "github.com/IBM/integrity-enforcer/shield/pkg/apis/shieldconfig/v1alpha1"
	sigconf "github.com/IBM/integrity-enforcer/shield/pkg/apis/signerconfig/v1alpha1"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

/**********************************************

				CRD

***********************************************/

func (r *IntegrityShieldReconciler) createOrUpdateCRD(instance *apiv1alpha1.IntegrityShield, expected *extv1.CustomResourceDefinition) (ctrl.Result, error) {
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

func (r *IntegrityShieldReconciler) deleteCRD(instance *apiv1alpha1.IntegrityShield, expected *extv1.CustomResourceDefinition) (ctrl.Result, error) {
	ctx := context.Background()
	found := &extv1.CustomResourceDefinition{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"CustomResourceDefinition.Name", expected.Name)

	err := r.Get(ctx, types.NamespacedName{Name: expected.Name}, found)

	if err == nil {
		reqLogger.Info(fmt.Sprintf("Deleting the IShield CustomResourceDefinition %s", expected.Name))
		err = r.Delete(ctx, found)
		if err != nil {
			reqLogger.Error(err, fmt.Sprintf("Failed to delete the IShield CustomResourceDefinition %s", expected.Name))
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if errors.IsNotFound(err) {
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else {
		return ctrl.Result{}, err
	}

}

func (r *IntegrityShieldReconciler) createOrUpdateShieldConfigCRD(
	instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildShieldConfigCRD(instance)
	return r.createOrUpdateCRD(instance, expected)
}

func (r *IntegrityShieldReconciler) createOrUpdateSignerConfigCRD(
	instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildSignerConfigCRD(instance)
	return r.createOrUpdateCRD(instance, expected)
}
func (r *IntegrityShieldReconciler) createOrUpdateResourceSignatureCRD(
	instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildResourceSignatureCRD(instance)
	return r.createOrUpdateCRD(instance, expected)
}

func (r *IntegrityShieldReconciler) createOrUpdateHelmReleaseMetadataCRD(
	instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildHelmReleaseMetadataCRD(instance)
	return r.createOrUpdateCRD(instance, expected)
}

func (r *IntegrityShieldReconciler) createOrUpdateResourceSigningProfileCRD(
	instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildResourceSigningProfileCRD(instance)
	return r.createOrUpdateCRD(instance, expected)
}

// func (r *IntegrityShieldReconciler) createOrUpdateProtectedResourceIntegrityCRD(
// 	instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
// 	expected := res.BuildProtectedResourceIntegrityCRD(instance)
// 	return r.createOrUpdateCRD(instance, expected)
// }

func (r *IntegrityShieldReconciler) deleteShieldConfigCRD(
	instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildShieldConfigCRD(instance)
	return r.deleteCRD(instance, expected)
}

func (r *IntegrityShieldReconciler) deleteSignerConfigCRD(
	instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildSignerConfigCRD(instance)
	return r.deleteCRD(instance, expected)
}
func (r *IntegrityShieldReconciler) deleteResourceSignatureCRD(
	instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildResourceSignatureCRD(instance)
	return r.deleteCRD(instance, expected)
}

func (r *IntegrityShieldReconciler) deleteHelmReleaseMetadataCRD(
	instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildHelmReleaseMetadataCRD(instance)
	return r.deleteCRD(instance, expected)
}

func (r *IntegrityShieldReconciler) deleteResourceSigningProfileCRD(
	instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildResourceSigningProfileCRD(instance)
	return r.deleteCRD(instance, expected)
}

// func (r *IntegrityShieldReconciler) deleteProtectedResourceIntegrityCRD(
// 	instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
// 	expected := res.BuildProtectedResourceIntegrityCRD(instance)
// 	return r.deleteCRD(instance, expected)
// }

/**********************************************

				CR

***********************************************/

func getCommonProfilesPath() []string {
	commonProfileDir := apiv1alpha1.CommonProfilesPath

	_, err := os.Stat(apiv1alpha1.CommonProfilesPath)
	if err != nil && os.IsNotExist(err) {
		// when this func is called in unit test, use correct path for test
		currentDir, _ := os.Getwd()
		commonProfileDir = filepath.Join(currentDir, "../", apiv1alpha1.CommonProfilesPath)
	}

	files, _ := ioutil.ReadDir(commonProfileDir)

	yamlPaths := []string{}
	for _, f := range files {
		fpath := filepath.Join(commonProfileDir, f.Name())
		if strings.HasSuffix(fpath, ".yaml") {
			yamlPaths = append(yamlPaths, fpath)
		}
	}
	return yamlPaths
}

func (r *IntegrityShieldReconciler) createOrUpdateShieldConfigCR(instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	ctx := context.Background()

	expected := res.BuildShieldConfigForIShield(instance, r.Scheme, getCommonProfilesPath())
	found := &ec.ShieldConfig{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"ShieldConfig.Name", expected.Name)

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

func (r *IntegrityShieldReconciler) createOrUpdateSignerConfigCR(instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	ctx := context.Background()
	found := &sigconf.SignerConfig{}
	expected := res.BuildSignerConfigForIShield(instance)

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"SignerConfig.Name", expected.Name)

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

func (r *IntegrityShieldReconciler) createOrUpdateResourceSigningProfileCR(instance *apiv1alpha1.IntegrityShield, prof *apiv1alpha1.ProfileConfig) (ctrl.Result, error) {
	ctx := context.Background()
	found := &rsp.ResourceSigningProfile{}
	expected := res.BuildResourceSigningProfileForIShield(instance, prof)
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

func (r *IntegrityShieldReconciler) createOrUpdateServiceAccount(instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	ctx := context.Background()
	expected := res.BuildServiceAccountForIShield(instance)
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

func (r *IntegrityShieldReconciler) createOrUpdateClusterRole(instance *apiv1alpha1.IntegrityShield, expected *rbacv1.ClusterRole) (ctrl.Result, error) {
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

func (r *IntegrityShieldReconciler) deleteClusterRole(instance *apiv1alpha1.IntegrityShield, expected *rbacv1.ClusterRole) (ctrl.Result, error) {
	ctx := context.Background()
	found := &rbacv1.ClusterRole{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"ClusterRole.Name", expected.Name)

	err := r.Get(ctx, types.NamespacedName{Name: expected.Name}, found)

	if err == nil {
		reqLogger.Info(fmt.Sprintf("Deleting the IShield ClusterRole %s", expected.Name))
		err = r.Delete(ctx, found)
		if err != nil {
			reqLogger.Error(err, fmt.Sprintf("Failed to delete the IShield ClusterRole %s", expected.Name))
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if errors.IsNotFound(err) {

		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else {
		return ctrl.Result{}, err
	}

}

func (r *IntegrityShieldReconciler) createOrUpdateClusterRoleBinding(instance *apiv1alpha1.IntegrityShield, expected *rbacv1.ClusterRoleBinding) (ctrl.Result, error) {
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

func (r *IntegrityShieldReconciler) deleteClusterRoleBinding(instance *apiv1alpha1.IntegrityShield, expected *rbacv1.ClusterRoleBinding) (ctrl.Result, error) {
	ctx := context.Background()
	found := &rbacv1.ClusterRoleBinding{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"ClusterRoleBinding.Name", expected.Name)

	err := r.Get(ctx, types.NamespacedName{Name: expected.Name}, found)

	if err == nil {
		reqLogger.Info(fmt.Sprintf("Deleting the IShield ClusterRoleBinding %s", expected.Name))
		err = r.Delete(ctx, found)
		if err != nil {
			reqLogger.Error(err, fmt.Sprintf("Failed to delete the IShield ClusterRoleBinding %s", expected.Name))
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if errors.IsNotFound(err) {
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else {
		return ctrl.Result{}, err
	}

}

func (r *IntegrityShieldReconciler) createOrUpdateRole(instance *apiv1alpha1.IntegrityShield, expected *rbacv1.Role) (ctrl.Result, error) {
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

func (r *IntegrityShieldReconciler) createOrUpdateRoleBinding(instance *apiv1alpha1.IntegrityShield, expected *rbacv1.RoleBinding) (ctrl.Result, error) {
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

// ishield-admin
func (r *IntegrityShieldReconciler) createOrUpdateClusterRoleBindingForIShieldAdmin(
	instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildClusterRoleBindingForIShieldAdmin(instance)
	return r.createOrUpdateClusterRoleBinding(instance, expected)
}

func (r *IntegrityShieldReconciler) deleteClusterRoleBindingForIShieldAdmin(
	instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildClusterRoleBindingForIShieldAdmin(instance)
	return r.deleteClusterRoleBinding(instance, expected)
}

func (r *IntegrityShieldReconciler) createOrUpdateRoleBindingForIShieldAdmin(
	instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildRoleBindingForIShieldAdmin(instance)
	return r.createOrUpdateRoleBinding(instance, expected)
}

func (r *IntegrityShieldReconciler) createOrUpdateRoleForIShieldAdmin(
	instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildRoleForIShieldAdmin(instance)
	return r.createOrUpdateRole(instance, expected)
}

func (r *IntegrityShieldReconciler) createOrUpdateClusterRoleForIShieldAdmin(
	instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildClusterRoleForIShieldAdmin(instance)
	return r.createOrUpdateClusterRole(instance, expected)
}

func (r *IntegrityShieldReconciler) deleteClusterRoleForIShieldAdmin(
	instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildClusterRoleForIShieldAdmin(instance)
	return r.deleteClusterRole(instance, expected)
}

// for ie
func (r *IntegrityShieldReconciler) createOrUpdateClusterRoleBindingForIShield(
	instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildClusterRoleBindingForIShield(instance)
	return r.createOrUpdateClusterRoleBinding(instance, expected)
}

func (r *IntegrityShieldReconciler) deleteClusterRoleBindingForIShield(
	instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildClusterRoleBindingForIShield(instance)
	return r.deleteClusterRoleBinding(instance, expected)
}

func (r *IntegrityShieldReconciler) createOrUpdateRoleBindingForIShield(
	instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildRoleBindingForIShield(instance)
	return r.createOrUpdateRoleBinding(instance, expected)
}

func (r *IntegrityShieldReconciler) createOrUpdateRoleForIShield(
	instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildRoleForIShield(instance)
	return r.createOrUpdateRole(instance, expected)
}

func (r *IntegrityShieldReconciler) createOrUpdateClusterRoleForIShield(
	instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildClusterRoleForIShield(instance)
	return r.createOrUpdateClusterRole(instance, expected)
}

func (r *IntegrityShieldReconciler) deleteClusterRoleForIShield(
	instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildClusterRoleForIShield(instance)
	return r.deleteClusterRole(instance, expected)
}

func (r *IntegrityShieldReconciler) createOrUpdatePodSecurityPolicy(instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
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

// delete ishield-psp
func (r *IntegrityShieldReconciler) deletePodSecurityPolicy(instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	ctx := context.Background()
	expected := res.BuildPodSecurityPolicy(instance)
	found := &policyv1.PodSecurityPolicy{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"PodSecurityPolicy.Name", expected.Name)

	err := r.Get(ctx, types.NamespacedName{Name: expected.Name}, found)

	if err == nil {
		reqLogger.Info("Deleting the IShield PodSecurityPolicy")
		err = r.Delete(ctx, found)
		if err != nil {
			reqLogger.Error(err, "Failed to delete the IShield PodSecurityPolicy")
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if errors.IsNotFound(err) {
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else {
		return ctrl.Result{}, err
	}
}

/**********************************************

				Secret

***********************************************/

func (r *IntegrityShieldReconciler) isKeyRingReady(instance *apiv1alpha1.IntegrityShield) (bool, string) {
	ctx := context.Background()
	found := &corev1.Secret{}
	okCount := 0
	nonReadyKey := ""
	namedKeyCount := 0
	for _, keyConf := range instance.Spec.KeyConfig {
		if keyConf.SecretName == "" {
			continue
		}

		namedKeyCount += 1
		err := r.Get(ctx, types.NamespacedName{Name: keyConf.SecretName, Namespace: instance.Namespace}, found)
		if err == nil {
			okCount += 1
		} else {
			nonReadyKey = keyConf.SecretName
			break
		}
	}
	ok := (okCount == namedKeyCount)
	return ok, nonReadyKey
}

func (r *IntegrityShieldReconciler) createOrUpdateSecret(instance *apiv1alpha1.IntegrityShield, expected *corev1.Secret) (ctrl.Result, error) {
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

func addCertValues(instance *apiv1alpha1.IntegrityShield, expected *corev1.Secret, serviceName string) *corev1.Secret {
	reqLogger := log.WithValues(
		"Secret.Namespace", instance.Namespace,
		"Instance.Name", instance.Name,
		"Secret.Name", expected.Name)

	// generate and put certs
	ca, tlsKey, tlsCert, err := cert.GenerateCert(serviceName, instance.Namespace)
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

func (r *IntegrityShieldReconciler) createOrUpdateTlsSecret(
	instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildTlsSecretForIShield(instance)
	expected = addCertValues(instance, expected, instance.GetWebhookServiceName())
	return r.createOrUpdateSecret(instance, expected)
}

func (r *IntegrityShieldReconciler) createOrUpdateAPITlsSecret(
	instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildAPITlsSecretForIShield(instance)
	expected = addCertValues(instance, expected, instance.GetAPIServiceName())
	return r.createOrUpdateSecret(instance, expected)
}

func (r *IntegrityShieldReconciler) createOrUpdateSigStoreRootCertSecret(
	instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	expected, err := res.BuildSigStoreDefaultRootSecretForIShield(instance)
	if err != nil {
		reqLogger := r.Log.WithValues(
			"Instance.Name", instance.Name,
			"Secret.Name", expected.Name,
		)
		reqLogger.Error(err, "Error occured while downloading root cert. The creating secret will have empty value.")
	}
	return r.createOrUpdateSecret(instance, expected)
}

/**********************************************

				ConfigMap

***********************************************/

// func (r *IntegrityShieldReconciler) createOrUpdateConfigMap(instance *apiv1alpha1.IntegrityShield, expected *v1.ConfigMap) (ctrl.Result, error) {
// 	ctx := context.Background()
// 	found := &corev1.ConfigMap{}

// 	reqLogger := r.Log.WithValues(
// 		"Instance.Name", instance.Name,
// 		"ConfigMap.Name", expected.Name)

// 	// Set CR instance as the owner and controller
// 	err := controllerutil.SetControllerReference(instance, expected, r.Scheme)
// 	if err != nil {
// 		reqLogger.Error(err, "Failed to define expected resource")
// 		return ctrl.Result{}, err
// 	}

// 	// If ConfigMap does not exist, create it and requeue
// 	err = r.Get(ctx, types.NamespacedName{Name: expected.Name, Namespace: instance.Namespace}, found)

// 	if err != nil && errors.IsNotFound(err) {
// 		reqLogger.Info("Creating a new resource")
// 		err = r.Create(ctx, expected)
// 		if err != nil && errors.IsAlreadyExists(err) {
// 			// Already exists from previous reconcile, requeue.
// 			reqLogger.Info("Skip reconcile: resource already exists")
// 			return ctrl.Result{Requeue: true}, nil
// 		} else if err != nil {
// 			reqLogger.Error(err, "Failed to create new resource")
// 			return ctrl.Result{}, err
// 		}
// 		// Created successfully - return and requeue
// 		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
// 	} else if err != nil {
// 		return ctrl.Result{}, err
// 	}

// 	// No extra validation

// 	// No reconcile was necessary
// 	return ctrl.Result{}, nil
// }

/**********************************************

				Deployment

***********************************************/

func (r *IntegrityShieldReconciler) createOrUpdateDeployment(instance *apiv1alpha1.IntegrityShield, expected *appsv1.Deployment) (ctrl.Result, error) {
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
		reqLogger.Info("Updating IntegrityShield Controller Deployment", "Deployment.Name", found.Name)
		// Spec updated - return and requeue
		return ctrl.Result{Requeue: true}, nil
	}

	// No extra validation

	// No reconcile was necessary
	return ctrl.Result{}, nil

}

func (r *IntegrityShieldReconciler) createOrUpdateWebhookDeployment(instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildDeploymentForIShield(instance)
	return r.createOrUpdateDeployment(instance, expected)
}

// func (r *IntegrityShieldReconciler) createOrUpdateInspectorDeployment(instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
// 	expected := res.BuildInspectorDeploymentForIShield(instance)
// 	return r.createOrUpdateDeployment(instance, expected)
// }

func (r *IntegrityShieldReconciler) createOrUpdateAPIDeployment(instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildAPIDeploymentForIShield(instance)
	return r.createOrUpdateDeployment(instance, expected)
}

/**********************************************

				Service

***********************************************/

func (r *IntegrityShieldReconciler) createOrUpdateService(instance *apiv1alpha1.IntegrityShield, expected *corev1.Service) (ctrl.Result, error) {
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

func (r *IntegrityShieldReconciler) createOrUpdateWebhookService(instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildServiceForIShield(instance)
	return r.createOrUpdateService(instance, expected)
}

func (r *IntegrityShieldReconciler) createOrUpdateAPIService(instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	expected := res.BuildAPIServiceForIShield(instance)
	return r.createOrUpdateService(instance, expected)
}

/**********************************************

				Webhook

***********************************************/

func (r *IntegrityShieldReconciler) createOrUpdateWebhook(instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	ctx := context.Background()
	expected := res.BuildMutatingWebhookConfigurationForIShield(instance)
	found := &admregv1.MutatingWebhookConfiguration{}

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
		evtName := fmt.Sprintf("ishield-webhook-reconciled")
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
func (r *IntegrityShieldReconciler) deleteWebhook(instance *apiv1alpha1.IntegrityShield) (ctrl.Result, error) {
	ctx := context.Background()
	expected := res.BuildMutatingWebhookConfigurationForIShield(instance)
	found := &admregv1.MutatingWebhookConfiguration{}

	reqLogger := r.Log.WithValues(
		"Instance.Name", instance.Name,
		"MutatingWebhookConfiguration.Name", expected.Name)

	err := r.Get(ctx, types.NamespacedName{Name: expected.Name}, found)

	if err == nil {
		reqLogger.Info("Deleting the IShield webhook")
		err = r.Delete(ctx, found)
		if err != nil {
			reqLogger.Error(err, "Failed to delete the IShield Webhook")
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
func (r *IntegrityShieldReconciler) isDeploymentAvailable(instance *apiv1alpha1.IntegrityShield) bool {
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

func (r *IntegrityShieldReconciler) createOrUpdateWebhookEvent(instance *apiv1alpha1.IntegrityShield, evtName, webhookName string) error {
	ctx := context.Background()
	evtNamespace := instance.Namespace
	involvedObject := v1.ObjectReference{
		Namespace:  evtNamespace,
		APIVersion: instance.APIVersion,
		Kind:       instance.Kind,
		Name:       instance.Name,
	}
	now := time.Now()
	evtSourceName := "IntegrityShield"
	reason := "webhook-reconciled"
	msg := fmt.Sprintf("[IntegrityShieldEvent] IntegrityShield reconciled MutatingWebhookConfiguration \"%s\"", webhookName)
	expected := &v1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      evtName,
			Namespace: evtNamespace,
			Annotations: map[string]string{
				common.EventTypeAnnotationKey: common.EventTypeValueReconcileReport,
			},
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
		Reason:              reason,
		Count:               1,
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
