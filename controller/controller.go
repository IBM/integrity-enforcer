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

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	rareviewv1alpha1 "github.com/IBM/integrity-enforcer/controller/pkg/apis/resourceauditreview/v1alpha1"
	clientset "github.com/IBM/integrity-enforcer/controller/pkg/client/resourceauditreview/clientset/versioned"
	rareviewscheme "github.com/IBM/integrity-enforcer/controller/pkg/client/resourceauditreview/clientset/versioned/scheme"
	informers "github.com/IBM/integrity-enforcer/controller/pkg/client/resourceauditreview/informers/externalversions/resourceauditreview/v1alpha1"
	listers "github.com/IBM/integrity-enforcer/controller/pkg/client/resourceauditreview/listers/resourceauditreview/v1alpha1"
	"github.com/IBM/integrity-enforcer/shield/pkg/shield"
	"github.com/IBM/integrity-enforcer/shield/pkg/util/kubeutil"
)

const controllerAgentName = "resourceauditreview-controller"

const defaultIShieldAPIURL = "https://integrity-shield-api:8123"
const ishieldAPIURLEnv = "ISHIELD_API_URL"

const (
	// SuccessSynced is used as part of the Event 'reason' when a ResourceAuditReview is synced
	SuccessSynced = "Synced"
	// ErrResourceExists is used as part of the Event 'reason' when a ResourceAuditReview fails
	// to sync due to a Deployment of the same name already existing.
	ErrResourceExists = "ErrResourceExists"

	// MessageResourceExists is the message used for Events when a resource
	// fails to sync due to a Deployment already existing
	MessageResourceExists = "Resource %q already exists and is not managed by ResourceAuditReview"
	// MessageResourceSynced is the message used for an Event fired when a ResourceAuditReview
	// is synced successfully
	MessageResourceSynced = "ResourceAuditReview synced successfully"
)

var httpClient *http.Client

func init() {
	httpClient = new(http.Client)
	httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
}

// Controller is the controller implementation for ResourceAuditReview resources
type Controller struct {
	// kubeclientset is a standard kubernetes clientset
	kubeclientset kubernetes.Interface
	// rareviewclientset is a clientset for our own API group
	rareviewclientset clientset.Interface

	rarsLister listers.ResourceAuditReviewLister
	rarsSynced cache.InformerSynced

	// workqueue is a rate limited work queue. This is used to queue work to be
	// processed instead of performing it as soon as a change happens. This
	// means we can ensure we only process a fixed amount of resources at a
	// time, and makes it easy to ensure we are never processing the same item
	// simultaneously in two different workers.
	workqueue workqueue.RateLimitingInterface
	// recorder is an event recorder for recording Event resources to the
	// Kubernetes API.
	recorder record.EventRecorder
}

// NewController returns a new sample controller
func NewController(
	kubeclientset kubernetes.Interface,
	rareviewclientset clientset.Interface,
	rarInformer informers.ResourceAuditReviewInformer) *Controller {

	// Create event broadcaster
	// Add sample-controller types to the default Kubernetes Scheme so Events can be
	// logged for sample-controller types.
	utilruntime.Must(rareviewscheme.AddToScheme(scheme.Scheme))
	klog.V(4).Info("Creating event broadcaster")
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartStructuredLogging(0)
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: kubeclientset.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: controllerAgentName})

	controller := &Controller{
		kubeclientset:     kubeclientset,
		rareviewclientset: rareviewclientset,
		rarsLister:        rarInformer.Lister(),
		rarsSynced:        rarInformer.Informer().HasSynced,
		workqueue:         workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "ResourceAuditReviews"),
		recorder:          recorder,
	}

	klog.Info("Setting up event handlers")
	// Set up an event handler for when ResourceAuditReview resources change
	rarInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueResourceAuditReview,
		UpdateFunc: func(old, new interface{}) {
			controller.enqueueResourceAuditReview(new)
		},
	})

	return controller
}

// Run will set up the event handlers for types we are interested in, as well
// as syncing informer caches and starting workers. It will block until stopCh
// is closed, at which point it will shutdown the workqueue and wait for
// workers to finish processing their current work items.
func (c *Controller) Run(threadiness int, stopCh <-chan struct{}) error {
	defer utilruntime.HandleCrash()
	defer c.workqueue.ShutDown()

	// Start the informer factories to begin populating the informer caches
	klog.Info("Starting ResourceAuditReview controller")

	// Wait for the caches to be synced before starting workers
	klog.Info("Waiting for informer caches to sync")
	if ok := cache.WaitForCacheSync(stopCh, c.rarsSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	klog.Info("Starting workers")
	// Launch two workers to process ResourceAuditReview resources
	for i := 0; i < threadiness; i++ {
		go wait.Until(c.runWorker, time.Second, stopCh)
	}

	klog.Info("Started workers")
	<-stopCh
	klog.Info("Shutting down workers")

	return nil
}

// runWorker is a long-running function that will continually call the
// processNextWorkItem function in order to read and process a message on the
// workqueue.
func (c *Controller) runWorker() {
	for c.processNextWorkItem() {
	}
}

// processNextWorkItem will read a single work item off the workqueue and
// attempt to process it, by calling the syncHandler.
func (c *Controller) processNextWorkItem() bool {
	obj, shutdown := c.workqueue.Get()

	if shutdown {
		return false
	}

	// We wrap this block in a func so we can defer c.workqueue.Done.
	err := func(obj interface{}) error {
		// We call Done here so the workqueue knows we have finished
		// processing this item. We also must remember to call Forget if we
		// do not want this work item being re-queued. For example, we do
		// not call Forget if a transient error occurs, instead the item is
		// put back on the workqueue and attempted again after a back-off
		// period.
		defer c.workqueue.Done(obj)
		var key string
		var ok bool
		// We expect strings to come off the workqueue. These are of the
		// form namespace/name. We do this as the delayed nature of the
		// workqueue means the items in the informer cache may actually be
		// more up to date that when the item was initially put onto the
		// workqueue.
		if key, ok = obj.(string); !ok {
			// As the item in the workqueue is actually invalid, we call
			// Forget here else we'd go into a loop of attempting to
			// process a work item that is invalid.
			c.workqueue.Forget(obj)
			utilruntime.HandleError(fmt.Errorf("expected string in workqueue but got %#v", obj))
			return nil
		}
		// Run the syncHandler, passing it the namespace/name string of the
		// ResourceAuditReview resource to be synced.
		if err := c.syncHandler(key); err != nil {
			// Put the item back on the workqueue to handle any transient errors.
			c.workqueue.AddRateLimited(key)
			return fmt.Errorf("error syncing '%s': %s, requeuing", key, err.Error())
		}
		// Finally, if no error occurs we Forget this item so it does not
		// get queued again until another change happens.
		c.workqueue.Forget(obj)
		klog.Infof("Successfully synced '%s'", key)
		return nil
	}(obj)

	if err != nil {
		utilruntime.HandleError(err)
		return true
	}

	return true
}

// syncHandler compares the actual state with the desired, and attempts to
// converge the two. It then updates the Status block of the ResourceAuditReview resource
// with the current status of the resource.
func (c *Controller) syncHandler(key string) error {
	// Convert the namespace/name string into a distinct namespace and name
	_, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	// Get the ResourceAuditReview resource with this namespace/name
	rar, err := c.rarsLister.Get(name)
	if err != nil {
		// The ResourceAuditReview resource may no longer exist, in which case we stop
		// processing.
		if errors.IsNotFound(err) {
			utilruntime.HandleError(fmt.Errorf("rar '%s' in work queue no longer exists", key))
			return nil
		}

		return err
	}

	resAttrs := rar.Spec.ResourceAttributes
	fmt.Println("[DEBUG] resAttrs: ", resAttrs)

	gv := metav1.GroupVersion{Group: resAttrs.Group, Version: resAttrs.Version}
	apiVersion := gv.String()
	kind := resAttrs.Kind
	namespace := resAttrs.Namespace
	resname := resAttrs.Name
	obj, err := kubeutil.GetResource(apiVersion, kind, namespace, resname)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("resource not found; apiVersion: %s, kind: %s, namespace: %s, name: %s", apiVersion, kind, namespace, name))
		return nil
	}

	dr, ctx, err := resourceCheck(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("error returned from integrity shield api; %s", err.Error()))
		return nil
	}

	// Finally, we update the status block of the ResourceAuditReview resource to reflect the
	// current state of the world
	err = c.updateResourceAuditReviewStatus(rar, dr, ctx)
	if err != nil {
		return err
	}

	c.recorder.Event(rar, corev1.EventTypeNormal, SuccessSynced, MessageResourceSynced)
	return nil
}

func (c *Controller) updateResourceAuditReviewStatus(rar *rareviewv1alpha1.ResourceAuditReview, dr *shield.DecisionResult, ctx *shield.CheckContext) error {
	// NEVER modify objects from the store. It's a read-only, local cache.
	// You can use DeepCopy() to make a deep copy of original object and modify this copy
	// Or create a copy manually for better performance
	rarCopy := rar.DeepCopy()

	rarCopy.Status.Audit = dr.IsAllowed()
	rarCopy.Status.Protected = ctx.Protected
	rarCopy.Status.Signer = ctx.SignatureEvalResult.SignerName
	rarCopy.Status.Message = ctx.Message
	rarCopy.Status.LastUpdated = metav1.NewTime(time.Now().UTC())

	// If the CustomResourceSubresources feature gate is not enabled,
	// we must use Update instead of UpdateStatus to update the Status block of the ResourceAuditReview resource.
	// UpdateStatus will not allow changes to the Spec of the resource,
	// which is ideal for ensuring nothing other than resource status has been updated.
	_, err := c.rareviewclientset.ApisV1alpha1().ResourceAuditReviews().Update(context.TODO(), rarCopy, metav1.UpdateOptions{})
	return err
}

// enqueueResourceAuditReview takes a ResourceAuditReview resource and converts it into a namespace/name
// string which is then put onto the work queue. This method should *not* be
// passed resources of any type other than ResourceAuditReview.
func (c *Controller) enqueueResourceAuditReview(obj interface{}) {
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		return
	}
	c.workqueue.Add(key)
}

// handleObject will take any resource implementing metav1.Object and attempt
// to find the ResourceAuditReview resource that 'owns' it. It does this by looking at the
// objects metadata.ownerReferences field for an appropriate OwnerReference.
// It then enqueues that ResourceAuditReview resource to be processed. If the object does not
// have an appropriate OwnerReference, it will simply be skipped.
func (c *Controller) handleObject(obj interface{}) {
	var object metav1.Object
	var ok bool
	if object, ok = obj.(metav1.Object); !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("error decoding object, invalid type"))
			return
		}
		object, ok = tombstone.Obj.(metav1.Object)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("error decoding object tombstone, invalid type"))
			return
		}
		klog.V(4).Infof("Recovered deleted object '%s' from tombstone", object.GetName())
	}
	klog.V(4).Infof("Processing object: %s", object.GetName())
	if ownerRef := metav1.GetControllerOf(object); ownerRef != nil {
		// If this object is not owned by a ResourceAuditReview, we should not do anything more
		// with it.
		if ownerRef.Kind != "ResourceAuditReview" {
			return
		}

		rar, err := c.rarsLister.Get(ownerRef.Name)
		if err != nil {
			klog.V(4).Infof("ignoring orphaned object '%s' of rar '%s'", object.GetSelfLink(), ownerRef.Name)
			return
		}

		c.enqueueResourceAuditReview(rar)
		return
	}
}

func ishieldAPIURl() string {
	url := os.Getenv(ishieldAPIURLEnv)
	if url == "" {
		url = defaultIShieldAPIURL
	}
	return url
}

func resourceCheck(obj *unstructured.Unstructured) (*shield.DecisionResult, *shield.CheckContext, error) {
	objB, _ := json.Marshal(obj)
	dataB := bytes.NewBuffer(objB)
	url := ishieldAPIURl() + "/api/resource"

	req, err := http.NewRequest("POST", url, dataB)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Add("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	result, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	dr, ctx := parseResourceAPIResult(result)

	return dr, ctx, nil
}

func parseResourceAPIResult(result []byte) (*shield.DecisionResult, *shield.CheckContext) {
	var dr *shield.DecisionResult
	var ctx *shield.CheckContext

	var m map[string]interface{}
	_ = json.Unmarshal(result, &m)
	drB, _ := json.Marshal(m["result"])
	ctxB, _ := json.Marshal(m["context"])
	_ = json.Unmarshal(drB, &dr)
	_ = json.Unmarshal(ctxB, &ctx)
	return dr, ctx
}
