//
// Copyright 2021 IBM Corporation
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

package config

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeclient "k8s.io/client-go/kubernetes"
)

const defaultKeyInConfigMap = "config.yaml"
const defaultConstraintConfigName = "constraint-config"

// Constraint Config
type ConstraintConfig struct {
	Constraints []ActionConfig `json:"constraints,omitempty"`
}

type ActionConfig struct {
	ConstraintName string `json:"constraintName,omitempty"`
	Action         Action `json:"action,omitempty"`
}

type Action struct {
	Inform  bool `json:"inform,omitempty"`
	Enforce bool `json:"enforce,omitempty"`
}

type Rule struct {
	Match   []string `json:"match,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}

func LoadConstraintConfig() (ConstraintConfig, error) {
	var empty ConstraintConfig
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		namespace = defaultPodNamespace
	}
	configName := os.Getenv("CONSTRAINT_CONFIG_NAME")
	if configName == "" {
		configName = defaultConstraintConfigName
	}
	configKey := os.Getenv("CONSTRAINT_CONFIG_KEY")
	if configKey == "" {
		configKey = defaultKeyInConfigMap
	}

	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		return empty, err
	}
	clientset, err := kubeclient.NewForConfig(config)
	if err != nil {
		log.Error(err)
		return empty, err
	}
	cm, err := clientset.CoreV1().ConfigMaps(namespace).Get(context.Background(), configName, metav1.GetOptions{})
	if err != nil {
		return empty, errors.Wrap(err, fmt.Sprintf("failed to get a configmap `%s` in `%s` namespace", configName, namespace))
	}
	cfgBytes, found := cm.Data[configKey]
	if !found {
		return empty, errors.New(fmt.Sprintf("`%s` is not found in configmap", configKey))
	}
	var tr *ConstraintConfig
	err = yaml.Unmarshal([]byte(cfgBytes), &tr)
	if err != nil {
		return empty, errors.Wrap(err, fmt.Sprintf("failed to unmarshal config.yaml into %T", tr))
	}
	if tr == nil {
		return empty, nil
	}
	return *tr, nil
}

func MatchPattern(pattern, value string) bool {
	if pattern == "" {
		return true
	} else if pattern == "*" {
		return true
	} else if pattern == "-" && value == "" {
		return true
	} else if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(value, strings.TrimRight(pattern, "*"))
	} else if pattern == value {
		return true
	} else {
		return false
	}
}

// exclude from observation
func CheckIfIgnoredConstraint(constraintName string, aconfigs []ActionConfig) bool {
	matched := []bool{}
	for _, conf := range aconfigs {
		nameMatched := MatchPattern(conf.ConstraintName, constraintName)
		if nameMatched {
			matched = append(matched, conf.Action.Inform)
		}
	}
	ignored := false
	for _, inform := range matched {
		if !inform {
			ignored = true
		}
	}
	return ignored
}

// not block even if invalid request
func CheckIfEnforceConstraint(constraintName string, aconfigs []ActionConfig) bool {
	matched := []bool{}
	for _, conf := range aconfigs {
		nameMatched := MatchPattern(conf.ConstraintName, constraintName)
		if nameMatched {
			matched = append(matched, conf.Action.Enforce)
		}
	}
	enforce := false
	for _, e := range matched {
		if e {
			enforce = true
		}
	}
	return enforce
}
