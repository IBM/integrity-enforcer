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

package integrityenforcer

import (
	"context"
	"time"

	researchv1alpha1 "github.com/IBM/integrity-enforcer/operator/pkg/apis/research/v1alpha1"
	"github.com/IBM/integrity-enforcer/operator/pkg/pgpkey"
	res "github.com/IBM/integrity-enforcer/operator/pkg/resources"
	scc "github.com/openshift/api/security/v1"
	admv1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"

	cert "github.com/IBM/integrity-enforcer/operator/pkg/cert"

	epol "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/enforcepolicy/v1alpha1"
	ec "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/enforcerconfig/v1alpha1"
	rs "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/resourcesignature/v1alpha1"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

/**********************************************

				CRD

***********************************************/

func (r *ReconcileIntegrityEnforcer) createOrUpdateCRD(instance *researchv1alpha1.IntegrityEnforcer, expected *extv1.CustomResourceDefinition) (reconcile.Result, error) {

	found := &extv1.CustomResourceDefinition{}

	reqLogger := log.WithValues(
		"Instance.Name", instance.Name,
		"CRD.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return reconcile.Result{}, err
	}

	// If CRD does not exist, create it and requeue
	err = r.client.Get(context.TODO(), types.NamespacedName{Name: expected.Name, Namespace: ""}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.client.Create(context.TODO(), expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return reconcile.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return reconcile.Result{}, err
		}
		// Created successfully - return and requeue
		return reconcile.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return reconcile.Result{}, nil

}

func (r *ReconcileIntegrityEnforcer) createOrUpdateEnforcerConfigCRD(
	instance *researchv1alpha1.IntegrityEnforcer) (reconcile.Result, error) {
	expected := res.BuildEnforcerConfigCRD(instance)
	return r.createOrUpdateCRD(instance, expected)
}

func (r *ReconcileIntegrityEnforcer) createOrUpdateEnforcePolicyCRD(
	instance *researchv1alpha1.IntegrityEnforcer) (reconcile.Result, error) {
	expected := res.BuildEnforcePolicyCRD(instance)
	return r.createOrUpdateCRD(instance, expected)
}

func (r *ReconcileIntegrityEnforcer) createOrUpdateResourceSignatureCRD(
	instance *researchv1alpha1.IntegrityEnforcer) (reconcile.Result, error) {
	expected := res.BuildResourceSignatureCRD(instance)
	return r.createOrUpdateCRD(instance, expected)
}

/**********************************************

				CR

***********************************************/

func (r *ReconcileIntegrityEnforcer) createOrUpdateEnforcerConfigCR(instance *researchv1alpha1.IntegrityEnforcer) (reconcile.Result, error) {
	expected := res.BuildEnforcerConfigForIE(instance)
	found := &ec.EnforcerConfig{}

	reqLogger := log.WithValues(
		"Instance.Name", instance.Name,
		"EnforcerConfig.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return reconcile.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.client.Get(context.TODO(), types.NamespacedName{Name: expected.Name, Namespace: instance.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.client.Create(context.TODO(), expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return reconcile.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return reconcile.Result{}, err
		}
		// Created successfully - return and requeue
		return reconcile.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return reconcile.Result{}, nil

}

func (r *ReconcileIntegrityEnforcer) createOrUpdateEnforcePolicyCR(instance *researchv1alpha1.IntegrityEnforcer, expected *epol.EnforcePolicy) (reconcile.Result, error) {
	found := &epol.EnforcePolicy{}

	reqLogger := log.WithValues(
		"Instance.Name", instance.Name,
		"EnforcePolicy.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return reconcile.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.client.Get(context.TODO(), types.NamespacedName{Name: expected.Name, Namespace: instance.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.client.Create(context.TODO(), expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return reconcile.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return reconcile.Result{}, err
		}
		// Created successfully - return and requeue
		return reconcile.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return reconcile.Result{}, nil

}

func (r *ReconcileIntegrityEnforcer) createOrUpdateIntegrityEnforcerEnforcePolicyCR(instance *researchv1alpha1.IntegrityEnforcer) (reconcile.Result, error) {
	expected := res.BuildIntegrityEnforcerEnforcePolicyForIE(instance)
	return r.createOrUpdateEnforcePolicyCR(instance, expected)
}

func (r *ReconcileIntegrityEnforcer) createOrUpdateDefaultEnforcePolicyCR(instance *researchv1alpha1.IntegrityEnforcer) (reconcile.Result, error) {
	expected := res.BuildDefaultEnforcePolicyForIE(instance)
	return r.createOrUpdateEnforcePolicyCR(instance, expected)
}

func (r *ReconcileIntegrityEnforcer) createOrUpdateSignerEnforcePolicyCR(instance *researchv1alpha1.IntegrityEnforcer) (reconcile.Result, error) {
	expected := res.BuildSignerEnforcePolicyForIE(instance)
	return r.createOrUpdateEnforcePolicyCR(instance, expected)
}

func (r *ReconcileIntegrityEnforcer) createOrUpdateResourceSignatureCR(instance *researchv1alpha1.IntegrityEnforcer) (reconcile.Result, error) {
	expected := res.BuildResourceSignatureForCR(instance)
	found := &rs.ResourceSignature{}

	reqLogger := log.WithValues(
		"Instance.Name", instance.Name,
		"ResourceSignature.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return reconcile.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.client.Get(context.TODO(), types.NamespacedName{Name: expected.Name, Namespace: instance.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.client.Create(context.TODO(), expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return reconcile.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return reconcile.Result{}, err
		}
		// Created successfully - return and requeue
		return reconcile.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return reconcile.Result{}, nil

}

/**********************************************

				Role

***********************************************/

func (r *ReconcileIntegrityEnforcer) createOrUpdateSCC(instance *researchv1alpha1.IntegrityEnforcer) (reconcile.Result, error) {

	expected := res.BuildSecurityContextConstraints(instance)
	found := &scc.SecurityContextConstraints{}
	found.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "security.openshift.io",
		Kind:    "SecurityContextConstraints",
		Version: "v1",
	})

	reqLogger := log.WithValues(
		"Instance.Name", instance.Name,
		"SecurityContextConstraints.Name", expected.Name)

	// // Set CR instance as the owner and controller
	// err := controllerutil.SetControllerReference(instance, expected, r.scheme)
	// if err != nil {
	// 	reqLogger.Error(err, "Failed to define expected resource")
	// 	return reconcile.Result{}, err
	// }

	err := r.client.Get(context.Background(), types.NamespacedName{Name: expected.Name, Namespace: ""}, found)

	if err != nil && errors.IsNotFound(err) {
		// Define a new ClusterRole
		reqLogger.Info("Creating a new SCC", "SCC.Name", expected)
		err = r.client.Create(context.TODO(), expected)
		if err != nil {
			reqLogger.Error(err, "Failed to create new SCC", "SCC.Name", expected)
			return reconcile.Result{}, err
		}
		// ClusterRole created successfully - return and requeue
		return reconcile.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		reqLogger.Error(err, "Failed to get SCC")
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

func (r *ReconcileIntegrityEnforcer) createOrUpdateServiceAccount(instance *researchv1alpha1.IntegrityEnforcer) (reconcile.Result, error) {

	expected := res.BuildServiceAccountForIE(instance)
	found := &corev1.ServiceAccount{}

	reqLogger := log.WithValues(
		"Instance.Name", instance.Name,
		"ServiceAccount.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return reconcile.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.client.Get(context.TODO(), types.NamespacedName{Name: expected.Name, Namespace: instance.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.client.Create(context.TODO(), expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return reconcile.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return reconcile.Result{}, err
		}
		// Created successfully - return and requeue
		return reconcile.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return reconcile.Result{}, nil

}

func (r *ReconcileIntegrityEnforcer) createOrUpdateClusterRole(instance *researchv1alpha1.IntegrityEnforcer) (reconcile.Result, error) {

	expected := res.BuildClusterRoleForIE(instance)
	found := &rbacv1.ClusterRole{}

	reqLogger := log.WithValues(
		"ClusterRole.Namespace", instance.Namespace,
		"Instance.Name", instance.Name,
		"ClusterRole.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return reconcile.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.client.Get(context.TODO(), types.NamespacedName{Name: expected.Name}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.client.Create(context.TODO(), expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return reconcile.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return reconcile.Result{}, err
		}
		// Created successfully - return and requeue
		return reconcile.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return reconcile.Result{}, nil

}

func (r *ReconcileIntegrityEnforcer) createOrUpdateClusterRoleBinding(instance *researchv1alpha1.IntegrityEnforcer) (reconcile.Result, error) {

	expected := res.BuildClusterRoleBindingForIE(instance)
	found := &rbacv1.ClusterRoleBinding{}

	reqLogger := log.WithValues(
		"Instance.Name", instance.Name,
		"RoleBinding.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return reconcile.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.client.Get(context.TODO(), types.NamespacedName{Name: expected.Name}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.client.Create(context.TODO(), expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return reconcile.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return reconcile.Result{}, err
		}
		// Created successfully - return and requeue
		return reconcile.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return reconcile.Result{}, nil

}

func (r *ReconcileIntegrityEnforcer) createOrUpdateRole(instance *researchv1alpha1.IntegrityEnforcer) (reconcile.Result, error) {

	expected := res.BuildRoleForIE(instance)
	found := &rbacv1.Role{}

	reqLogger := log.WithValues(
		"Role.Namespace", instance.Namespace,
		"Instance.Name", instance.Name,
		"Role.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return reconcile.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.client.Get(context.TODO(), types.NamespacedName{Namespace: instance.Namespace, Name: expected.Name}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.client.Create(context.TODO(), expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return reconcile.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return reconcile.Result{}, err
		}
		// Created successfully - return and requeue
		return reconcile.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return reconcile.Result{}, nil

}

func (r *ReconcileIntegrityEnforcer) createOrUpdateRoleBinding(instance *researchv1alpha1.IntegrityEnforcer) (reconcile.Result, error) {

	expected := res.BuildRoleBindingForIE(instance)
	found := &rbacv1.RoleBinding{}

	reqLogger := log.WithValues(
		"Instance.Name", instance.Name,
		"RoleBinding.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return reconcile.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.client.Get(context.TODO(), types.NamespacedName{Namespace: instance.Namespace, Name: expected.Name}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.client.Create(context.TODO(), expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return reconcile.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return reconcile.Result{}, err
		}
		// Created successfully - return and requeue
		return reconcile.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return reconcile.Result{}, nil

}

func (r *ReconcileIntegrityEnforcer) createOrUpdatePodSecurityPolicy(instance *researchv1alpha1.IntegrityEnforcer) (reconcile.Result, error) {

	expected := res.BuildPodSecurityPolicy(instance)
	found := &policyv1.PodSecurityPolicy{}

	reqLogger := log.WithValues(
		"Instance.Name", instance.Name,
		"PodSecurityPolicy.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return reconcile.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.client.Get(context.TODO(), types.NamespacedName{Name: expected.Name}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.client.Create(context.TODO(), expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return reconcile.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return reconcile.Result{}, err
		}
		// Created successfully - return and requeue
		return reconcile.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return reconcile.Result{}, nil

}

/**********************************************

				Secret

***********************************************/

func (r *ReconcileIntegrityEnforcer) createOrUpdateSecret(instance *researchv1alpha1.IntegrityEnforcer, expected *corev1.Secret) (reconcile.Result, error) {

	found := &corev1.Secret{}

	reqLogger := log.WithValues(
		"Secret.Namespace", instance.Namespace,
		"Instance.Name", instance.Name,
		"Secret.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return reconcile.Result{}, err
	}

	// If CRD does not exist, create it and requeue
	err = r.client.Get(context.TODO(), types.NamespacedName{Name: expected.Name, Namespace: instance.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {

		reqLogger.Info("Creating a new resource")
		err = r.client.Create(context.TODO(), expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return reconcile.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return reconcile.Result{}, err
		}
		// Created successfully - return and requeue
		return reconcile.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return reconcile.Result{}, nil

}

func (r *ReconcileIntegrityEnforcer) createOrUpdateCertSecret(instance *researchv1alpha1.IntegrityEnforcer, expected *corev1.Secret) (reconcile.Result, error) {

	found := &corev1.Secret{}

	reqLogger := log.WithValues(
		"Secret.Namespace", instance.Namespace,
		"Instance.Name", instance.Name,
		"Secret.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return reconcile.Result{}, err
	}

	// If CRD does not exist, create it and requeue
	err = r.client.Get(context.TODO(), types.NamespacedName{Name: expected.Name, Namespace: instance.Namespace}, found)

	expected = addCertValues(instance, expected)

	if err != nil && errors.IsNotFound(err) {

		reqLogger.Info("Creating a new resource")
		err = r.client.Create(context.TODO(), expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return reconcile.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return reconcile.Result{}, err
		}
		// Created successfully - return and requeue
		return reconcile.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return reconcile.Result{}, nil

}

func addCertValues(instance *researchv1alpha1.IntegrityEnforcer, expected *corev1.Secret) *corev1.Secret {
	reqLogger := log.WithValues(
		"Secret.Namespace", instance.Namespace,
		"Instance.Name", instance.Name,
		"Secret.Name", expected.Name)

	// generate and put certs
	ca, tlsKey, tlsCert, err := cert.GenerateCert(instance.Spec.WebhookServiceName, instance.Namespace)
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

func (r *ReconcileIntegrityEnforcer) createOrUpdateRegKeySecret(
	instance *researchv1alpha1.IntegrityEnforcer) (reconcile.Result, error) {
	expected := res.BuildRegKeySecretForCR(instance)
	return r.createOrUpdateSecret(instance, expected)
}

func (r *ReconcileIntegrityEnforcer) createOrUpdateKeyringSecret(
	instance *researchv1alpha1.IntegrityEnforcer) (reconcile.Result, error) {
	expected := res.BuildKeyringSecretForIEFromValue(instance)
	pubkeyName := pgpkey.GetPublicKeyringName()
	expected.Data[pubkeyName] = instance.Spec.KeyRing.KeyValue
	return r.createOrUpdateSecret(instance, expected)
}

func (r *ReconcileIntegrityEnforcer) createOrUpdateTlsSecret(
	instance *researchv1alpha1.IntegrityEnforcer) (reconcile.Result, error) {
	expected := res.BuildTlsSecretForIE(instance)
	return r.createOrUpdateCertSecret(instance, expected)
}

/**********************************************

				Deployment

***********************************************/

func (r *ReconcileIntegrityEnforcer) createOrUpdateDeployment(instance *researchv1alpha1.IntegrityEnforcer, expected *appsv1.Deployment) (reconcile.Result, error) {

	found := &appsv1.Deployment{}

	reqLogger := log.WithValues(
		"Instance.Name", instance.Name,
		"Deployment.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return reconcile.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.client.Get(context.TODO(), types.NamespacedName{Name: expected.Name, Namespace: instance.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.client.Create(context.TODO(), expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return reconcile.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return reconcile.Result{}, err
		}
		// Created successfully - return and requeue
		return reconcile.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	} else if !res.EqualDeployments(expected, found) {
		// If spec is incorrect, update it and requeue
		found.ObjectMeta.Labels = expected.ObjectMeta.Labels
		found.Spec = expected.Spec
		err = r.client.Update(context.TODO(), found)
		if err != nil {
			reqLogger.Error(err, "Failed to update Deployment", "Namespace", instance.Namespace, "Name", found.Name)
			return reconcile.Result{}, err
		}
		reqLogger.Info("Updating IntegrityEnforcer Controller Deployment", "Deployment.Name", found.Name)
		// Spec updated - return and requeue
		return reconcile.Result{Requeue: true}, nil
	}

	// No extra validation

	// No reconcile was necessary
	return reconcile.Result{}, nil

}

func (r *ReconcileIntegrityEnforcer) createOrUpdateWebhookDeployment(instance *researchv1alpha1.IntegrityEnforcer) (reconcile.Result, error) {
	expected := res.BuildDeploymentForCR(instance)
	return r.createOrUpdateDeployment(instance, expected)
}

/**********************************************

				Service

***********************************************/

func (r *ReconcileIntegrityEnforcer) createOrUpdateService(instance *researchv1alpha1.IntegrityEnforcer, expected *corev1.Service) (reconcile.Result, error) {
	found := &corev1.Service{}

	reqLogger := log.WithValues(
		"Instance.Name", instance.Name,
		"Instance.Spec.ServiceName", instance.Spec.WebhookServiceName,
		"Service.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return reconcile.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.client.Get(context.TODO(), types.NamespacedName{Name: expected.Name, Namespace: instance.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		err = r.client.Create(context.TODO(), expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return reconcile.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return reconcile.Result{}, err
		}
		// Created successfully - return and requeue
		return reconcile.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return reconcile.Result{}, nil
}

func (r *ReconcileIntegrityEnforcer) createOrUpdateWebhookService(instance *researchv1alpha1.IntegrityEnforcer) (reconcile.Result, error) {
	expected := res.BuildServiceForCR(instance)
	return r.createOrUpdateService(instance, expected)
}

/**********************************************

				Webhook

***********************************************/

func (r *ReconcileIntegrityEnforcer) createOrUpdateWebhook(instance *researchv1alpha1.IntegrityEnforcer) (reconcile.Result, error) {

	expected := res.BuildMutatingWebhookConfigurationForIE(instance)
	found := &admv1.MutatingWebhookConfiguration{}

	reqLogger := log.WithValues(
		"Instance.Name", instance.Name,
		"MutatingWebhookConfiguration.Name", expected.Name)

	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expected, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return reconcile.Result{}, err
	}

	// If PodSecurityPolicy does not exist, create it and requeue
	err = r.client.Get(context.TODO(), types.NamespacedName{Name: expected.Name}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new resource")
		// locad cabundle
		secret := &corev1.Secret{}
		err = r.client.Get(context.TODO(), types.NamespacedName{Name: instance.Spec.WebhookServerTlsSecretName, Namespace: instance.Namespace}, secret)
		if err != nil {
			reqLogger.Error(err, "Fail to load CABundle from Secret")
		}
		cabundle, ok := secret.Data["ca.crt"]
		if ok {
			expected.Webhooks[0].ClientConfig.CABundle = cabundle
		}

		err = r.client.Create(context.TODO(), expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Skip reconcile: resource already exists")
			return reconcile.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new resource")
			return reconcile.Result{}, err
		}
		// Created successfully - return and requeue
		return reconcile.Result{Requeue: true, RequeueAfter: time.Second * 1}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// No extra validation

	// No reconcile was necessary
	return reconcile.Result{}, nil

}
