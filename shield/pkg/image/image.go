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
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
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
	cosigncli "github.com/sigstore/cosign/cmd/cosign/cli"
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
func VerifyImageInManifest(resource unstructured.Unstructured, profile ishieldconfig.ImageProfile) (bool, error) {
	yamlBytes, err := yaml.Marshal(resource.Object)
	if err != nil {
		return false, errors.Wrap(err, "failed to yaml.Marshal() the resource")
	}
	tmpDir, err := ioutil.TempDir("", "verify-image")
	if err != nil {
		return false, fmt.Errorf("failed to create temp dir: %s", err.Error())
	}
	defer os.RemoveAll(tmpDir)

	manifestPath := filepath.Join(tmpDir, "manifest.yaml")
	err = ioutil.WriteFile(manifestPath, yamlBytes, 0644)
	if err != nil {
		return false, fmt.Errorf("failed to create temp manifest file: %s", err.Error())
	}

	keyPathList := []string{}
	for _, keyConfig := range profile.KeyConfigs {
		if keyConfig.KeySecretName != "" {
			keyPath, err := ishieldconfig.LoadKeySecret(keyConfig.KeySecretNamespace, keyConfig.KeySecretName)
			if err != nil {
				return false, errors.Wrap(err, "failed to load a key secret for image verification")
			}
			keyPathList = append(keyPathList, keyPath)
		}
	}
	if len(keyPathList) == 0 {
		keyPathList = []string{""} // for keyless verification
	}

	allImagesVerified := false
	failReason := ""
	// overallFailReason := ""
	for _, keyPath := range keyPathList {
		cmd := cosigncli.VerifyManifestCommand{VerifyCommand: cosigncli.VerifyCommand{}}
		if keyPath != "" {
			cmd.KeyRef = keyPath
		}

		var verifiedWithThisKey bool
		var iErr error

		// currently cosigncli.VerifyManifestCommand.Exec() does not return detail information like image names and their signer names
		// TODO: create an issue in sigstore/cosign repository
		iErr = cmd.Exec(context.Background(), []string{manifestPath})
		if iErr == nil {
			verifiedWithThisKey = true
		} else {
			failReason = iErr.Error()
		}
		if verifiedWithThisKey {
			allImagesVerified = true
			break
		}
	}
	var retErr error
	if !allImagesVerified {
		retErr = errors.New(failReason)
	}

	return allImagesVerified, retErr
}

// this is a function from `cosign verify-manifest` codes
// ( https://github.com/sigstore/cosign/blob/v1.1.0/cmd/cosign/cli/verify_manifest.go#L120 )
//
// TODO: create an issue in cosign so that this function could be imported
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
