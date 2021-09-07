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

package image

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"

	ishieldconfig "github.com/IBM/integrity-shield/shield/pkg/config"
	k8smanifestcosign "github.com/sigstore/k8s-manifest-sigstore/pkg/cosign"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type ImageVerifyResult struct {
	Object     unstructured.Unstructured `json:"object"`
	ImageRef   string                    `json:"imageRef"`
	Verified   bool                      `json:"verified"`
	InScope    bool                      `json:"inScope"`
	Signer     string                    `json:"signer"`
	SignedTime *time.Time                `json:"signedTime"`
	FailReason string                    `json:"failReason"`
}

type ImageVerifyOption struct {
	KeyPath string
}

// verify all images in a container of the specified resource
func VerifyImageInManifest(resource unstructured.Unstructured, profile ishieldconfig.ImageProfile) ([]ImageVerifyResult, error) {
	yamlBytes, err := yaml.Marshal(resource.Object)
	if err != nil {
		return nil, errors.Wrap(err, "failed to yaml.Marshal() the resource")
	}

	imageRefList, err := getImagesFromYamlManifest(yamlBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get image references in a resource")
	}

	keyPathList := []string{}
	for _, keyConfig := range profile.KeyConfigs {
		if keyConfig.KeySecretName != "" {
			keyPath, err := ishieldconfig.LoadKeySecret(keyConfig.KeySecretNamespace, keyConfig.KeySecretName)
			if err != nil {
				return nil, errors.Wrap(err, "failed to load a key secret for image verification")
			}
			keyPathList = append(keyPathList, keyPath)
		}
	}
	if len(keyPathList) == 0 {
		keyPathList = []string{""} // for keyless verification
	}

	results := []ImageVerifyResult{}
	for _, imageRef := range imageRefList {
		inScope := profile.MatchWith(imageRef)
		if !inScope {
			results = append(results, ImageVerifyResult{Object: resource, ImageRef: imageRef, InScope: false})
			continue
		}

		verified := false
		signerName := ""
		failReason := ""
		for _, keyPath := range keyPathList {
			var verifiedWithThisKey bool
			var iErr error
			verifiedWithThisKey, signerName, _, iErr = k8smanifestcosign.VerifyImage(imageRef, keyPath)
			if !verifiedWithThisKey && iErr != nil {
				failReason = iErr.Error()
			}
			if verifiedWithThisKey {
				verified = true
				break
			}
		}
		r := ImageVerifyResult{
			Object:     resource,
			ImageRef:   imageRef,
			Verified:   verified,
			InScope:    true,
			Signer:     signerName,
			FailReason: failReason,
		}
		results = append(results, r)
	}
	return results, nil
}

// this is a function from `cosign verify-manifest` codes
// ( https://github.com/sigstore/cosign/blob/v1.1.0/cmd/cosign/cli/verify_manifest.go#L120 )
//
// TODO: create a PR in cosign to export the original function and remove this block
func getImagesFromYamlManifest(manifest []byte) ([]string, error) {
	dec := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(manifest), 4096)
	cScheme := runtime.NewScheme()
	var images []string
	if err := corev1.AddToScheme(cScheme); err != nil {
		return images, err
	}
	if err := appsv1.AddToScheme(cScheme); err != nil {
		return images, err
	}
	if err := batchv1.AddToScheme(cScheme); err != nil {
		return images, err
	}

	deserializer := serializer.NewCodecFactory(cScheme).UniversalDeserializer()
	for {
		ext := runtime.RawExtension{}
		if err := dec.Decode(&ext); err != nil {
			if err == io.EOF {
				break
			}
			return images, fmt.Errorf("unable to decode the manifest")
		}

		ext.Raw = bytes.TrimSpace(ext.Raw)
		if len(ext.Raw) == 0 || bytes.Equal(ext.Raw, []byte("null")) {
			continue
		}

		decoded, _, err := deserializer.Decode(ext.Raw, nil, nil)
		if err != nil {
			return images, fmt.Errorf("unable to decode the manifest")
		}

		var (
			d   *appsv1.Deployment
			rs  *appsv1.ReplicaSet
			ss  *appsv1.StatefulSet
			ds  *appsv1.DaemonSet
			job *batchv1.CronJob
			pod *corev1.Pod
		)
		containers := make([]corev1.Container, 0)
		switch obj := decoded.(type) {
		case *appsv1.Deployment:
			d = obj
			containers = append(containers, d.Spec.Template.Spec.Containers...)
			containers = append(containers, d.Spec.Template.Spec.InitContainers...)
			for _, c := range containers {
				images = append(images, c.Image)
			}
		case *appsv1.DaemonSet:
			ds = obj
			containers = append(containers, ds.Spec.Template.Spec.Containers...)
			containers = append(containers, ds.Spec.Template.Spec.InitContainers...)
			for _, c := range containers {
				images = append(images, c.Image)
			}
		case *appsv1.ReplicaSet:
			rs = obj
			containers = append(containers, rs.Spec.Template.Spec.Containers...)
			containers = append(containers, rs.Spec.Template.Spec.InitContainers...)
			for _, c := range containers {
				images = append(images, c.Image)
			}
		case *appsv1.StatefulSet:
			ss = obj
			containers = append(containers, ss.Spec.Template.Spec.Containers...)
			containers = append(containers, ss.Spec.Template.Spec.InitContainers...)
			for _, c := range containers {
				images = append(images, c.Image)
			}

		case *batchv1.CronJob:
			job = obj
			containers = append(containers, job.Spec.JobTemplate.Spec.Template.Spec.Containers...)
			containers = append(containers, job.Spec.JobTemplate.Spec.Template.Spec.InitContainers...)
			for _, c := range containers {
				images = append(images, c.Image)
			}
		case *corev1.Pod:
			pod = obj
			containers = append(containers, pod.Spec.Containers...)
			containers = append(containers, pod.Spec.InitContainers...)

			for _, c := range containers {
				images = append(images, c.Image)
			}
		}
	}

	return images, nil
}
