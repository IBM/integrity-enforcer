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

package shield

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	common "github.com/IBM/integrity-enforcer/shield/pkg/common"

	"github.com/IBM/integrity-enforcer/shield/pkg/util/kubeutil"
	appsv1 "k8s.io/api/apps/v1"
	appsv1beta1 "k8s.io/api/apps/v1beta1"
	appsv1beta2 "k8s.io/api/apps/v1beta2"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	batchv2alpha1 "k8s.io/api/batch/v2alpha1"
	corev1 "k8s.io/api/core/v1"
	extensionsv1beta1 "k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

type ImageDecisionResult struct {
	Type     common.DecisionType `json:"type,omitempty"`
	Verified bool                `json:"verified,omitempty"`
	Allowed  bool                `json:"allowed,omitempty"`
	Message  string              `json:"message,omitempty"`
}

type SigCheckImages struct {
	ImagesToVerify []ImageToVerify `json:"imagesToVefiry"`
}

type ImageToVerify struct {
	Image              string            `json:"image"`
	Profile            ImageCheckProfile `json:"profile"`
	Result             ImageVerifyResult `json:"result"`
	ProfileCheckResult bool              `json:"profileCheckResult"`
}

type ImageVerifyResult struct {
	Error       error    `json:"error"`
	Allowed     bool     `json:"allowed"`
	Reason      string   `json:"reason"`
	Digest      string   `json:"digest"`
	CommonNames []string `json:"commonNames"`
}

type ImageCheckProfile struct {
	Key                string `json:"key"`
	KeyNamespace       string `json:"keyNamespace"`
	CommonName         string `json:"commonName"`
	Image              string `json:"image"`
	CosignExperimental bool   `json:"cosignExperimental"`
}

func requestCheckForImageCheck(resc *common.ResourceContext) (bool, *SigCheckImages, string) {
	// return sigcheck, image, msg
	// scope check
	inscope := filterByKind(resc.Kind)
	if !inscope {
		// no image referenced
		fmt.Println("no image referenced")
		return false, nil, "no image referenced"
	}
	// get images
	podspec, err := getPodSpec(resc.RawObject, resc.ApiGroup, resc.ApiVersion, resc.Kind)
	if err != nil {
		// "no image referenced: fail to get podspec"
		fmt.Println("no image referenced: fail to get podspec")
		return false, nil, "no image referenced: fail to get podspec"
	}
	images := getImages(podspec.Containers)
	imagesToVerify, msg := getImageProfile(resc.Namespace, images)
	if len(imagesToVerify) == 0 {
		return false, nil, msg
	}
	sigCheckImages := &SigCheckImages{
		ImagesToVerify: imagesToVerify,
	}
	return true, sigCheckImages, ""
}

func (sci *SigCheckImages) imageVerifiedResultCheckByProfile() {
	for i, img := range sci.ImagesToVerify {
		if contains(img.Result.CommonNames, img.Profile.CommonName) {
			img.ProfileCheckResult = true
			sci.ImagesToVerify[i] = img
		}
	}
}

func makeImageCheckResult(images *SigCheckImages) *ImageDecisionResult {
	res := &ImageDecisionResult{}
	for _, img := range images.ImagesToVerify {
		if img.Result.Error != nil {
			res.Type = common.DecisionError
			res.Allowed = false
			res.Verified = true
			res.Message = img.Result.Error.Error()
			return res
		}
		if !img.Result.Allowed {
			res.Type = common.DecisionDeny
			res.Allowed = false
			res.Verified = true
			res.Message = img.Result.Reason
			return res
		}
		if !img.ProfileCheckResult {
			res.Type = common.DecisionDeny
			res.Allowed = false
			res.Verified = true
			res.Message = "no image profile matches with this commonName:" + strings.Join(img.Result.CommonNames, ",")
			return res
		}
	}
	res.Allowed = true
	res.Verified = true
	res.Type = common.DecisionAllow
	res.Message = "image " + images.ImagesToVerify[0].Result.Digest + " is signed by " + images.ImagesToVerify[0].Profile.CommonName
	return res
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func getImageProfile(namespace string, images []string) ([]ImageToVerify, string) {
	var imagesToVerify []ImageToVerify
	// load image profile
	ip, err := getConfigmapProfile(namespace, "image-profile-cm")
	if err != nil {
		return imagesToVerify, "fail to load image profile"
	}
	// check if there are policies for the given image
	for _, img := range images {
		if isMatchImage(ip.Image, img) {
			var imageToVerify ImageToVerify
			imageToVerify.Image = img
			imageToVerify.Profile.CommonName = ip.CommonName
			imageToVerify.Profile.CosignExperimental = ip.CosignExperimental
			imageToVerify.Profile.Image = ip.Image
			imagesToVerify = append(imagesToVerify, imageToVerify)
		}
	}
	if len(imagesToVerify) == 0 {
		return imagesToVerify, "No matching profile"
	}
	return imagesToVerify, ""
}

func isMatchImage(pattern, value string) bool {
	// profileImage, givenImage
	pattern = strings.TrimSpace(pattern)
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

func filterByKind(resource string) bool {
	if resource == "Pod" || resource == "Deployment" || resource == "Replicaset" || resource == "Daemonset" || resource == "Statefulset" || resource == "Job" || resource == "Cronjob" {
		return true
	}
	return false
}

func getImages(containers []corev1.Container) []string {
	var images []string
	for _, c := range containers {
		images = append(images, c.Image)
	}
	return images
}

func getConfigmapProfile(namespace, profileName string) (*ImageCheckProfile, error) {
	// Retrieve secret
	config, _ := kubeutil.GetKubeConfig()
	c, _ := corev1client.NewForConfig(config)
	cm, err := c.ConfigMaps(namespace).Get(context.Background(), profileName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	// Obtain the key data
	var imageProfile ImageCheckProfile
	if transparencyLog, ok := cm.Data["transparencyLog"]; ok {
		tlog, _ := strconv.ParseBool(transparencyLog)
		imageProfile.CosignExperimental = tlog
	}
	if cn, ok := cm.Data["commonName"]; ok {
		imageProfile.CommonName = cn
	}
	if key, ok := cm.Data["keySecret"]; ok {
		imageProfile.Key = key
	}
	if keySecretNamespace, ok := cm.Data["keySecretNamespace"]; ok {
		imageProfile.KeyNamespace = keySecretNamespace
	}
	if image, ok := cm.Data["image"]; ok {
		imageProfile.Image = image
		return &imageProfile, nil
	}
	return nil, fmt.Errorf("no image is defined in image profile configmap", namespace)
}

func getPodSpec(rawObj []byte, group, version, kind string) (*corev1.PodSpec, error) {
	ps := corev1.PodSpec{}
	if kind == "Pod" && version == "v1" {
		pod := corev1.Pod{}
		if err := json.Unmarshal(rawObj, &pod); err != nil {
			return nil, err
		}
		ps = pod.Spec
	} else if kind == "Deployment" && version == "v1" && group == "apps" {
		deployment := appsv1.Deployment{}
		if err := json.Unmarshal(rawObj, &deployment); err != nil {
			return nil, err
		}
		ps = deployment.Spec.Template.Spec
	} else if kind == "Deployment" && version == "v1beta1" && group == "apps" {
		deployment := appsv1beta1.Deployment{}
		if err := json.Unmarshal(rawObj, &deployment); err != nil {
			return nil, err
		}
		ps = deployment.Spec.Template.Spec
	} else if kind == "Deployment" && version == "v1beta2" && group == "apps" {
		deployment := appsv1beta2.Deployment{}
		if err := json.Unmarshal(rawObj, &deployment); err != nil {
			return nil, err
		}
		ps = deployment.Spec.Template.Spec
	} else if kind == "Deployment" && version == "v1beta1" && group == "extensions" {
		deployment := extensionsv1beta1.Deployment{}
		if err := json.Unmarshal(rawObj, &deployment); err != nil {
			return nil, err
		}
		ps = deployment.Spec.Template.Spec
	} else if kind == "Replicaset" && version == "v1" && group == "apps" {
		replicaset := appsv1.ReplicaSet{}
		if err := json.Unmarshal(rawObj, &replicaset); err != nil {
			return nil, err
		}
		ps = replicaset.Spec.Template.Spec
	} else if kind == "Replicaset" && version == "v1beta1" && group == "extensions" {
		replicaset := extensionsv1beta1.ReplicaSet{}
		if err := json.Unmarshal(rawObj, &replicaset); err != nil {
			return nil, err
		}
		ps = replicaset.Spec.Template.Spec
	} else if kind == "Replicaset" && version == "v1beta2" && group == "apps" {
		replicaset := appsv1beta2.ReplicaSet{}
		if err := json.Unmarshal(rawObj, &replicaset); err != nil {
			return nil, err
		}
		ps = replicaset.Spec.Template.Spec
	} else if kind == "DaemonSet" && version == "v1" && group == "apps" {
		daemonset := appsv1.DaemonSet{}
		if err := json.Unmarshal(rawObj, &daemonset); err != nil {
			return nil, err
		}
		ps = daemonset.Spec.Template.Spec
	} else if kind == "DaemonSet" && version == "v1beta2" && group == "apps" {
		daemonset := appsv1beta2.DaemonSet{}
		if err := json.Unmarshal(rawObj, &daemonset); err != nil {
			return nil, err
		}
		ps = daemonset.Spec.Template.Spec
	} else if kind == "DaemonSet" && version == "v1beta1" && group == "extensions" {
		daemonset := extensionsv1beta1.DaemonSet{}
		if err := json.Unmarshal(rawObj, &daemonset); err != nil {
			return nil, err
		}
		ps = daemonset.Spec.Template.Spec
	} else if kind == "StatefulSet" && version == "v1" && group == "apps" {
		statefulset := appsv1.StatefulSet{}
		if err := json.Unmarshal(rawObj, &statefulset); err != nil {
			return nil, err
		}
		ps = statefulset.Spec.Template.Spec
	} else if kind == "StatefulSet" && version == "v1beta2" && group == "apps" {
		statefulset := appsv1beta2.StatefulSet{}
		if err := json.Unmarshal(rawObj, &statefulset); err != nil {
			return nil, err
		}
		ps = statefulset.Spec.Template.Spec
	} else if kind == "StatefulSet" && version == "v1beta1" && group == "apps" {
		statefulset := appsv1beta1.StatefulSet{}
		if err := json.Unmarshal(rawObj, &statefulset); err != nil {
			return nil, err
		}
		ps = statefulset.Spec.Template.Spec
	} else if kind == "Job" && version == "v1" && group == "batch" {
		job := batchv1.Job{}
		if err := json.Unmarshal(rawObj, &job); err != nil {
			return nil, err
		}
		ps = job.Spec.Template.Spec
	} else if kind == "CronJob" && version == "v1beta1" && group == "batch" {
		cronjob := batchv1beta1.CronJob{}
		if err := json.Unmarshal(rawObj, &cronjob); err != nil {
			return nil, err
		}
		ps = cronjob.Spec.JobTemplate.Spec.Template.Spec
	} else if kind == "CronJob" && version == "v2alpha1" && group == "batch" {
		cronjob := batchv2alpha1.CronJob{}
		if err := json.Unmarshal(rawObj, &cronjob); err != nil {
			return nil, err
		}
		ps = cronjob.Spec.JobTemplate.Spec.Template.Spec
	}
	return &ps, nil
}
