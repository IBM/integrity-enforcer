package e2e

import (
	goctx "context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IsPodReady returns true if a pod is ready; false otherwise.
func IsPodReady(pod *corev1.Pod) bool {
	return IsPodReadyConditionTrue(pod.Status)
}

// IsPodReadyConditionTrue returns true if a pod is ready; false otherwise.
func IsPodReadyConditionTrue(status corev1.PodStatus) bool {
	condition := GetPodReadyCondition(status)
	return condition != nil && condition.Status == corev1.ConditionTrue
}

// GetPodReadyCondition extracts the pod ready condition from the given status and returns that.
// Returns nil if the condition is not present.
func GetPodReadyCondition(status corev1.PodStatus) *corev1.PodCondition {
	_, condition := GetPodCondition(&status, corev1.PodReady)
	return condition
}

// GetPodCondition extracts the provided condition from the given status and returns that.
// Returns nil and -1 if the condition is not present, and the index of the located condition.
func GetPodCondition(status *corev1.PodStatus, conditionType corev1.PodConditionType) (int, *corev1.PodCondition) {
	if status == nil {
		return -1, nil
	}
	for i := range status.Conditions {
		if status.Conditions[i].Type == conditionType {
			return i, &status.Conditions[i]
		}
	}
	return -1, nil
}

func IsTargetPodReadyConditionTrue(pods *corev1.PodList, expected string) (found, ready bool) {
	for _, pod := range pods.Items {
		if strings.HasPrefix(pod.Name, expected) {
			for _, pod := range pods.Items {
				if strings.HasPrefix(pod.Name, expected) {
					is_ready := IsPodReadyConditionTrue(pod.Status)
					return true, is_ready
				}
			}
		}
	}
	return false, false
}

func CheckPodStatus(framework *Framework, namespace, expected string) error {
	pods, err := framework.KubeClientSet.CoreV1().Pods(namespace).List(goctx.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}
	pod_exist, ready := IsTargetPodReadyConditionTrue(pods, expected)
	if !pod_exist {
		return fmt.Errorf("Pod is not found: %v", expected)
	}
	if pod_exist && !ready {
		return fmt.Errorf("Pod is not ready: %v", expected)
	}
	return nil
}

func CheckConfigMap(framework *Framework, namespace, expected string) error {
	_, err := framework.KubeClientSet.CoreV1().ConfigMaps(namespace).Get(goctx.TODO(), expected, metav1.GetOptions{})
	if err != nil {
		return err
	}
	return nil
}
