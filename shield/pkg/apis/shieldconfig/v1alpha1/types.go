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

package v1alpha1

import (
	config "github.com/IBM/integrity-enforcer/shield/pkg/config"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// StatePending means CRD instance is created; Pod info has been updated into CRD instance;
	// Pod has been accepted by the system, but one or more of the containers has not been started.
	StatePending string = "Pending"
	// StateRunning means Pod has been bound to a node and all of the containers have been started.
	StateRunning string = "Running"
	// StateSucceeded means that all containers in the Pod have voluntarily terminated with a container
	// exit code of 0, and the system is not going to restart any of these containers.
	StateSucceeded string = "Succeeded"
	// StateFailed means that all containers in the Pod have terminated, and at least one container has
	// terminated in a failure (exited with a non-zero exit code or was stopped by the system).
	StateFailed string = "Failed"
)

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +resource:path=shieldconfig,scope=Namespaced

// ShieldConfig is the CRD. Use this command to generate deepcopy for it:
// ./k8s.io/code-generator/generate-groups.sh all github.com/IBM/pas-client-go/pkg/crd/packageadmissionsignature/v1/apis github.com/IBM/pas-client-go/pkg/crd/ "packageadmissionsignature:v1"
// For more details of code-generator, please visit https://github.com/kubernetes/code-generator
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// ShieldConfig is the CRD. Use this command to generate deepcopy for it:
type ShieldConfig struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	metav1.ObjectMeta `json:"metadata"`
	// Specification of the desired behavior of ShieldConfig.
	Spec ShieldConfigSpec `json:"spec"`
	// Observed status of ShieldConfig.
	Status ShieldConfigStatus `json:"status"`
}

// ShieldConfigSpec is a desired state description of ShieldConfig.
type ShieldConfigSpec struct {
	ShieldConfig *config.ShieldConfig `json:",inline"`
}

// ShieldConfig describes the lifecycle status of ShieldConfig.
type ShieldConfigStatus struct {
	State   string `json:"state"`
	Message string `json:"message"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ShieldConfigList is a list of Workflow resources
type ShieldConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []*ShieldConfig `json:"items"`
}
