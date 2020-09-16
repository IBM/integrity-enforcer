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

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"time"

	v1alpha1 "github.com/IBM/integrity-enforcer/enforcer/pkg/apis/vsignpolicy/v1alpha1"
	scheme "github.com/IBM/integrity-enforcer/enforcer/pkg/client/vsignpolicy/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// VSignPoliciesGetter has a method to return a VSignPolicyInterface.
// A group's client should implement this interface.
type VSignPoliciesGetter interface {
	VSignPolicies(namespace string) VSignPolicyInterface
}

// VSignPolicyInterface has methods to work with VSignPolicy resources.
type VSignPolicyInterface interface {
	Create(*v1alpha1.VSignPolicy) (*v1alpha1.VSignPolicy, error)
	Update(*v1alpha1.VSignPolicy) (*v1alpha1.VSignPolicy, error)
	Delete(name string, options *v1.DeleteOptions) error
	DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error
	Get(name string, options v1.GetOptions) (*v1alpha1.VSignPolicy, error)
	List(opts v1.ListOptions) (*v1alpha1.VSignPolicyList, error)
	Watch(opts v1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.VSignPolicy, err error)
	VSignPolicyExpansion
}

// vSignPolicies implements VSignPolicyInterface
type vSignPolicies struct {
	client rest.Interface
	ns     string
}

// newVSignPolicies returns a VSignPolicies
func newVSignPolicies(c *ResearchV1alpha1Client, namespace string) *vSignPolicies {
	return &vSignPolicies{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the vSignPolicy, and returns the corresponding vSignPolicy object, and an error if there is any.
func (c *vSignPolicies) Get(name string, options v1.GetOptions) (result *v1alpha1.VSignPolicy, err error) {
	result = &v1alpha1.VSignPolicy{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("vsignpolicies").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of VSignPolicies that match those selectors.
func (c *vSignPolicies) List(opts v1.ListOptions) (result *v1alpha1.VSignPolicyList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.VSignPolicyList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("vsignpolicies").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do().
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested vSignPolicies.
func (c *vSignPolicies) Watch(opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("vsignpolicies").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch()
}

// Create takes the representation of a vSignPolicy and creates it.  Returns the server's representation of the vSignPolicy, and an error, if there is any.
func (c *vSignPolicies) Create(vSignPolicy *v1alpha1.VSignPolicy) (result *v1alpha1.VSignPolicy, err error) {
	result = &v1alpha1.VSignPolicy{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("vsignpolicies").
		Body(vSignPolicy).
		Do().
		Into(result)
	return
}

// Update takes the representation of a vSignPolicy and updates it. Returns the server's representation of the vSignPolicy, and an error, if there is any.
func (c *vSignPolicies) Update(vSignPolicy *v1alpha1.VSignPolicy) (result *v1alpha1.VSignPolicy, err error) {
	result = &v1alpha1.VSignPolicy{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("vsignpolicies").
		Name(vSignPolicy.Name).
		Body(vSignPolicy).
		Do().
		Into(result)
	return
}

// Delete takes name of the vSignPolicy and deletes it. Returns an error if one occurs.
func (c *vSignPolicies) Delete(name string, options *v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("vsignpolicies").
		Name(name).
		Body(options).
		Do().
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *vSignPolicies) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	var timeout time.Duration
	if listOptions.TimeoutSeconds != nil {
		timeout = time.Duration(*listOptions.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("vsignpolicies").
		VersionedParams(&listOptions, scheme.ParameterCodec).
		Timeout(timeout).
		Body(options).
		Do().
		Error()
}

// Patch applies the patch and returns the patched vSignPolicy.
func (c *vSignPolicies) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.VSignPolicy, err error) {
	result = &v1alpha1.VSignPolicy{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("vsignpolicies").
		SubResource(subresources...).
		Name(name).
		Body(data).
		Do().
		Into(result)
	return
}