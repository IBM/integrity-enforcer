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
