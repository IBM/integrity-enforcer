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

package signservice

import (
	"context"
	"time"

	researchv1alpha1 "github.com/IBM/integrity-enforcer/develop/signservice/signservice-operator/pkg/apis/research/v1alpha1"
	"github.com/IBM/integrity-enforcer/develop/signservice/signservice-operator/pkg/pkix"
	res "github.com/IBM/integrity-enforcer/develop/signservice/signservice-operator/pkg/resources"
	"github.com/IBM/integrity-enforcer/operator/pkg/cert"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

/**********************************************

				Secret

***********************************************/

func (r *ReconcileSignService) createOrUpdateSecret(instance *researchv1alpha1.SignService, expected *corev1.Secret) (reconcile.Result, error) {

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

// create 2 signer secrets for signservice and for ie at the same time
func (r *ReconcileSignService) createOrUpdateSignerCertSecret(
	instance *researchv1alpha1.SignService) (reconcile.Result, error) {

	// signservice-secret
	expected := res.BuildSignServiceSecretForIE(instance)

	reqLogger := log.WithValues(
		"Instance.Name", instance.Name,
		"Secret.Name", expected.Name)

	keyBoxList, err := pkix.CreateKeyBoxListFromSignerChain(instance.Spec.Signers)
	if err != nil {
		reqLogger.Error(err, "Failed to generate keyring.")
		return reconcile.Result{}, err
	}

	expected.Data = keyBoxList.ToSecretData()
	recResult, err := r.createOrUpdateSecret(instance, expected)
	if err != nil {
		reqLogger.Error(err, "Failed to generate keyring.")
		return recResult, err
	}

	// ie-certpool-secret
	expected2 := res.BuildIECertPoolSecretForIE(instance)
	expected2.Data = keyBoxList.ToCertPoolData()
	return r.createOrUpdateSecret(instance, expected2)
}

func addCertValues(instance *researchv1alpha1.SignService, expected *corev1.Secret) *corev1.Secret {
	reqLogger := log.WithValues(
		"Secret.Namespace", instance.Namespace,
		"Instance.Name", instance.Name,
		"Secret.Name", expected.Name)

	// generate and put certs
	ca, tlsKey, tlsCert, err := cert.GenerateCert(res.SignServiceServiceName, instance.Namespace)
	if err != nil {
		reqLogger.Error(err, "Failed to generate certs")
	}
	_, ok_tc := expected.Data["server.crt"]
	_, ok_tk := expected.Data["server.key"]
	_, ok_ca := expected.Data["ca.crt"]
	if ok_ca && ok_tc && ok_tk {
		expected.Data["server.crt"] = tlsCert
		expected.Data["server.key"] = tlsKey
		expected.Data["ca.crt"] = ca
	}
	return expected
}

func (r *ReconcileSignService) createOrUpdateServerCertSecret(
	instance *researchv1alpha1.SignService) (reconcile.Result, error) {

	expected := res.BuildServerCertSecretForIE(instance)
	expected = addCertValues(instance, expected)
	return r.createOrUpdateSecret(instance, expected)
}

/**********************************************

				Service Account

***********************************************/

func (r *ReconcileSignService) createOrUpdateServiceAccount(instance *researchv1alpha1.SignService) (reconcile.Result, error) {

	expected := res.BuildSignServiceServiceAccount(instance)
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

/**********************************************

				Role

***********************************************/

func (r *ReconcileSignService) createOrUpdateRole(instance *researchv1alpha1.SignService) (reconcile.Result, error) {

	expected := res.BuildSignServiceRole(instance)
	found := &rbacv1.Role{}

	reqLogger := log.WithValues(
		"Namespace", instance.Namespace,
		"Instance.Name", instance.Name,
		"Role.Name", expected.Name)

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

				Role Binding

***********************************************/

func (r *ReconcileSignService) createOrUpdateRoleBinding(instance *researchv1alpha1.SignService) (reconcile.Result, error) {

	expected := res.BuildSignServiceRoleBinding(instance)
	found := &rbacv1.RoleBinding{}

	reqLogger := log.WithValues(
		"Namespace", instance.Namespace,
		"Instance.Name", instance.Name,
		"RoleBinding.Name", expected.Name)

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

				Deployment

***********************************************/

func (r *ReconcileSignService) createOrUpdateDeployment(instance *researchv1alpha1.SignService, expected *appsv1.Deployment) (reconcile.Result, error) {

	found := &appsv1.Deployment{}

	reqLogger := log.WithValues(
		"Namespace", instance.Namespace,
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
	}

	// No extra validation

	// No reconcile was necessary
	return reconcile.Result{}, nil

}

func (r *ReconcileSignService) createOrUpdateSignServiceDeployment(instance *researchv1alpha1.SignService) (reconcile.Result, error) {
	expected := res.BuildSignServiceDeploymentForCR(instance)
	return r.createOrUpdateDeployment(instance, expected)
}

/**********************************************

				Service

***********************************************/

func (r *ReconcileSignService) createOrUpdateService(instance *researchv1alpha1.SignService, expected *corev1.Service) (reconcile.Result, error) {
	found := &corev1.Service{}

	reqLogger := log.WithValues(
		"Instance.Name", instance.Name,
		"Instance.Spec.ServiceName", res.SignServiceServiceName,
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

func (r *ReconcileSignService) createOrUpdateSignServiceService(instance *researchv1alpha1.SignService) (reconcile.Result, error) {
	expected := res.BuildSignServiceServiceForCR(instance)
	return r.createOrUpdateService(instance, expected)
}
