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

package e2e

import (
	goctx "context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func CheckEventNoSignature(framework *Framework, namespace, expected string) error {
	events, err := framework.KubeClientSet.CoreV1().Events(namespace).List(goctx.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}
	blocked := false
	for _, event := range events.Items {
		if event.Reason == "no-signature" && strings.HasSuffix(event.Name, expected) {
			blocked = true
		}
	}
	if !blocked {
		return fmt.Errorf("Fail to block: %v", expected)
	}
	return nil
}
