// +build !ignore_autogenerated

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

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha1

import (
	resourcesigningprofilev1alpha1 "github.com/IBM/integrity-enforcer/shield/pkg/apis/resourcesigningprofile/v1alpha1"
	"github.com/IBM/integrity-enforcer/shield/pkg/common"
	"k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *APIContainer) DeepCopyInto(out *APIContainer) {
	*out = *in
	if in.SecurityContext != nil {
		in, out := &in.SecurityContext, &out.SecurityContext
		*out = new(v1.SecurityContext)
		(*in).DeepCopyInto(*out)
	}
	in.Resources.DeepCopyInto(&out.Resources)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new APIContainer.
func (in *APIContainer) DeepCopy() *APIContainer {
	if in == nil {
		return nil
	}
	out := new(APIContainer)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertPoolConfig) DeepCopyInto(out *CertPoolConfig) {
	*out = *in
	if in.KeyValue != nil {
		in, out := &in.KeyValue, &out.KeyValue
		*out = make([]byte, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertPoolConfig.
func (in *CertPoolConfig) DeepCopy() *CertPoolConfig {
	if in == nil {
		return nil
	}
	out := new(CertPoolConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *EsConfig) DeepCopyInto(out *EsConfig) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EsConfig.
func (in *EsConfig) DeepCopy() *EsConfig {
	if in == nil {
		return nil
	}
	out := new(EsConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HttpConfig) DeepCopyInto(out *HttpConfig) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HttpConfig.
func (in *HttpConfig) DeepCopy() *HttpConfig {
	if in == nil {
		return nil
	}
	out := new(HttpConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IntegrityShield) DeepCopyInto(out *IntegrityShield) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IntegrityShield.
func (in *IntegrityShield) DeepCopy() *IntegrityShield {
	if in == nil {
		return nil
	}
	out := new(IntegrityShield)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IntegrityShield) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IntegrityShieldList) DeepCopyInto(out *IntegrityShieldList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]IntegrityShield, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IntegrityShieldList.
func (in *IntegrityShieldList) DeepCopy() *IntegrityShieldList {
	if in == nil {
		return nil
	}
	out := new(IntegrityShieldList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IntegrityShieldList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IntegrityShieldSpec) DeepCopyInto(out *IntegrityShieldSpec) {
	*out = *in
	if in.MaxSurge != nil {
		in, out := &in.MaxSurge, &out.MaxSurge
		*out = new(intstr.IntOrString)
		**out = **in
	}
	if in.MaxUnavailable != nil {
		in, out := &in.MaxUnavailable, &out.MaxUnavailable
		*out = new(intstr.IntOrString)
		**out = **in
	}
	if in.ReplicaCount != nil {
		in, out := &in.ReplicaCount, &out.ReplicaCount
		*out = new(int32)
		**out = **in
	}
	if in.MetaLabels != nil {
		in, out := &in.MetaLabels, &out.MetaLabels
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.SelectorLabels != nil {
		in, out := &in.SelectorLabels, &out.SelectorLabels
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.NodeSelector != nil {
		in, out := &in.NodeSelector, &out.NodeSelector
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.Affinity != nil {
		in, out := &in.Affinity, &out.Affinity
		*out = new(v1.Affinity)
		(*in).DeepCopyInto(*out)
	}
	if in.Tolerations != nil {
		in, out := &in.Tolerations, &out.Tolerations
		*out = make([]v1.Toleration, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.ImagePullSecrets != nil {
		in, out := &in.ImagePullSecrets, &out.ImagePullSecrets
		*out = make([]v1.LocalObjectReference, len(*in))
		copy(*out, *in)
	}
	in.Security.DeepCopyInto(&out.Security)
	if in.KeyConfig != nil {
		in, out := &in.KeyConfig, &out.KeyConfig
		*out = make([]KeyConfig, len(*in))
		copy(*out, *in)
	}
	in.Server.DeepCopyInto(&out.Server)
	in.Logger.DeepCopyInto(&out.Logger)
	in.Observer.DeepCopyInto(&out.Observer)
	in.API.DeepCopyInto(&out.API)
	in.RegKeySecret.DeepCopyInto(&out.RegKeySecret)
	if in.ShieldConfig != nil {
		in, out := &in.ShieldConfig, &out.ShieldConfig
		*out = (*in).DeepCopy()
	}
	if in.IgnoreRules != nil {
		in, out := &in.IgnoreRules, &out.IgnoreRules
		*out = make([]common.Rule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.IgnoreAttrs != nil {
		in, out := &in.IgnoreAttrs, &out.IgnoreAttrs
		*out = make([]common.AttrsPattern, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.SignerConfig != nil {
		in, out := &in.SignerConfig, &out.SignerConfig
		*out = (*in).DeepCopy()
	}
	if in.ResourceSigningProfiles != nil {
		in, out := &in.ResourceSigningProfiles, &out.ResourceSigningProfiles
		*out = make([]*ProfileConfig, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(ProfileConfig)
				(*in).DeepCopyInto(*out)
			}
		}
	}
	in.WebhookNamespacedResource.DeepCopyInto(&out.WebhookNamespacedResource)
	in.WebhookClusterResource.DeepCopyInto(&out.WebhookClusterResource)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IntegrityShieldSpec.
func (in *IntegrityShieldSpec) DeepCopy() *IntegrityShieldSpec {
	if in == nil {
		return nil
	}
	out := new(IntegrityShieldSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IntegrityShieldStatus) DeepCopyInto(out *IntegrityShieldStatus) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IntegrityShieldStatus.
func (in *IntegrityShieldStatus) DeepCopy() *IntegrityShieldStatus {
	if in == nil {
		return nil
	}
	out := new(IntegrityShieldStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *KeyConfig) DeepCopyInto(out *KeyConfig) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new KeyConfig.
func (in *KeyConfig) DeepCopy() *KeyConfig {
	if in == nil {
		return nil
	}
	out := new(KeyConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *LoggerContainer) DeepCopyInto(out *LoggerContainer) {
	*out = *in
	if in.Enabled != nil {
		in, out := &in.Enabled, &out.Enabled
		*out = new(bool)
		**out = **in
	}
	if in.SecurityContext != nil {
		in, out := &in.SecurityContext, &out.SecurityContext
		*out = new(v1.SecurityContext)
		(*in).DeepCopyInto(*out)
	}
	if in.HttpConfig != nil {
		in, out := &in.HttpConfig, &out.HttpConfig
		*out = new(HttpConfig)
		**out = **in
	}
	in.Resources.DeepCopyInto(&out.Resources)
	if in.EsConfig != nil {
		in, out := &in.EsConfig, &out.EsConfig
		*out = new(EsConfig)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LoggerContainer.
func (in *LoggerContainer) DeepCopy() *LoggerContainer {
	if in == nil {
		return nil
	}
	out := new(LoggerContainer)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ObserverContainer) DeepCopyInto(out *ObserverContainer) {
	*out = *in
	if in.Enabled != nil {
		in, out := &in.Enabled, &out.Enabled
		*out = new(bool)
		**out = **in
	}
	if in.SecurityContext != nil {
		in, out := &in.SecurityContext, &out.SecurityContext
		*out = new(v1.SecurityContext)
		(*in).DeepCopyInto(*out)
	}
	in.Resources.DeepCopyInto(&out.Resources)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ObserverContainer.
func (in *ObserverContainer) DeepCopy() *ObserverContainer {
	if in == nil {
		return nil
	}
	out := new(ObserverContainer)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ProfileConfig) DeepCopyInto(out *ProfileConfig) {
	*out = *in
	if in.ResourceSigningProfileSpec != nil {
		in, out := &in.ResourceSigningProfileSpec, &out.ResourceSigningProfileSpec
		*out = new(resourcesigningprofilev1alpha1.ResourceSigningProfileSpec)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ProfileConfig.
func (in *ProfileConfig) DeepCopy() *ProfileConfig {
	if in == nil {
		return nil
	}
	out := new(ProfileConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RegKeySecret) DeepCopyInto(out *RegKeySecret) {
	*out = *in
	if in.Value != nil {
		in, out := &in.Value, &out.Value
		*out = make([]byte, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RegKeySecret.
func (in *RegKeySecret) DeepCopy() *RegKeySecret {
	if in == nil {
		return nil
	}
	out := new(RegKeySecret)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SecurityConfig) DeepCopyInto(out *SecurityConfig) {
	*out = *in
	if in.PodSecurityContext != nil {
		in, out := &in.PodSecurityContext, &out.PodSecurityContext
		*out = new(v1.PodSecurityContext)
		(*in).DeepCopyInto(*out)
	}
	if in.IShieldAdminSubjects != nil {
		in, out := &in.IShieldAdminSubjects, &out.IShieldAdminSubjects
		*out = make([]rbacv1.Subject, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecurityConfig.
func (in *SecurityConfig) DeepCopy() *SecurityConfig {
	if in == nil {
		return nil
	}
	out := new(SecurityConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ServerContainer) DeepCopyInto(out *ServerContainer) {
	*out = *in
	if in.SecurityContext != nil {
		in, out := &in.SecurityContext, &out.SecurityContext
		*out = new(v1.SecurityContext)
		(*in).DeepCopyInto(*out)
	}
	in.Resources.DeepCopyInto(&out.Resources)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServerContainer.
func (in *ServerContainer) DeepCopy() *ServerContainer {
	if in == nil {
		return nil
	}
	out := new(ServerContainer)
	in.DeepCopyInto(out)
	return out
}
