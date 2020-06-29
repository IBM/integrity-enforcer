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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var log = logf.Log.WithName("controller_signservice")

/**
* USER ACTION REQUIRED: This is a scaffold file intended for the user to modify with their own Controller
* business logic.  Delete these comments after modifying this file.*
 */

// Add creates a new SignService Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileSignService{client: mgr.GetClient(), scheme: mgr.GetScheme()}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("signservice-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource SignService
	err = c.Watch(&source.Kind{Type: &researchv1alpha1.SignService{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	// TODO(user): Modify this to be the types you create that are owned by the primary resource
	// Watch for changes to secondary resource Pods and requeue the owner SignService
	err = c.Watch(&source.Kind{Type: &corev1.Pod{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &researchv1alpha1.SignService{},
	})
	if err != nil {
		return err
	}

	return nil
}

// blank assignment to verify that ReconcileSignService implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileSignService{}

// ReconcileSignService reconciles a SignService object
type ReconcileSignService struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
}

// Reconcile reads that state of the cluster for a SignService object and makes changes based on the state read
// and what is in the SignService.Spec
// TODO(user): Modify this Reconcile function to implement your Controller logic.  This example creates
// a Pod as an example
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileSignService) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling SignService")

	// Fetch the SignService instance
	instance := &researchv1alpha1.SignService{}
	err := r.client.Get(context.TODO(), request.NamespacedName, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}

	var recResult reconcile.Result
	var recErr error

	if instance.Spec.Enabled {
		//SignService Server Cert Secret
		recResult, recErr = r.createOrUpdateServerCertSecret(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}

		//SignService Secret
		// public and private keyring secrets are created at the same time
		recResult, recErr = r.createOrUpdateKeyringSecret(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}

		//SignService Deployment
		recResult, recErr = r.createOrUpdateServiceAccount(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}

		//SignService Deployment
		recResult, recErr = r.createOrUpdateRole(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}

		//SignService Deployment
		recResult, recErr = r.createOrUpdateRoleBinding(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}

		//SignService Deployment
		recResult, recErr = r.createOrUpdateSignServiceDeployment(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}

		//SignService Service
		recResult, recErr = r.createOrUpdateSignServiceService(instance)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}
	}

	reqLogger.Info("Reconciliation successful!", "Name", instance.Name)
	// since we updated the status in the CR, sleep 5 seconds to allow the CR to be refreshed.
	time.Sleep(5 * time.Second)

	return reconcile.Result{}, nil
}
