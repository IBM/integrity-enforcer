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

package yaml

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"strings"

	"github.com/IBM/integrity-enforcer/shield/pkg/common"
	"github.com/IBM/integrity-enforcer/shield/pkg/util/mapnode"
	yaml "gopkg.in/yaml.v2"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
)

type ResourceInfo struct {
	common.ResourceRef `json:""`
	raw                []byte
}

func FindSingleYaml(message []byte, apiVersion, kind, name, namespace string) (bool, []byte) {
	for _, ri := range ParseMessage(message) {
		if common.MatchPattern(apiVersion, ri.ApiVersion) &&
			common.MatchPattern(kind, ri.Kind) &&
			common.MatchPattern(name, ri.Name) &&
			(common.MatchPattern(namespace, ri.Namespace) || ri.Namespace == "") {
			return true, ri.raw
		}
	}
	return false, nil
}

func ParseMessage(message []byte) []ResourceInfo {
	msg := Base64decode(string(message))
	msg = Decompress(msg)
	r := bytes.NewReader([]byte(msg))
	dec := k8syaml.NewYAMLToJSONDecoder(r)
	var t interface{}
	resources := []ResourceInfo{}
	for dec.Decode(&t) == nil {
		tB, err := yaml.Marshal(t)
		if err != nil {
			continue
		}
		n, err := mapnode.NewFromYamlBytes(tB)
		if err != nil {
			continue
		}
		apiVersion := n.GetString("apiVersion")
		kind := n.GetString("kind")
		name := n.GetString("metadata.name")
		namespace := n.GetString("metadata.namespace")
		tmp := ResourceInfo{
			ResourceRef: common.ResourceRef{
				ApiVersion: apiVersion,
				Kind:       kind,
				Name:       name,
				Namespace:  namespace,
			},
			raw: tB,
		}
		resources = append(resources, tmp)
	}
	return resources
}

func Base64decode(str string) string {
	decBytes, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return ""
	}
	dec := string(decBytes)
	return dec
}

func Decompress(str string) string {
	if str == "" {
		return str
	}
	buffer := strings.NewReader(str)
	reader, err := gzip.NewReader(buffer)
	if err != nil {
		return str
	}
	output := bytes.Buffer{}
	_, err = output.ReadFrom(reader)
	if err != nil {
		return str
	}
	s := string(output.Bytes())
	return s
}
