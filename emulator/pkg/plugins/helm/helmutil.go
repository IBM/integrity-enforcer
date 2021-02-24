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

package helm

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path"

	"net/http"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

func GetPackageDir() string {
	packageDir := os.Getenv("PACKAGE_DIR")
	if packageDir == "" {
		packageDir = "/tmp"
	}
	return packageDir
}

func GetHelmPackageFilePath(chartName, chartVersion string) string {
	packageDir := GetPackageDir()
	fname := fmt.Sprintf("%s-%s.tgz", chartName, chartVersion)
	fpath := path.Join(packageDir, fname)
	return fpath
}

func GetHelmProvFilePath(chartName, chartVersion string) string {
	packageDir := GetPackageDir()
	fname := fmt.Sprintf("%s-%s.tgz.prov", chartName, chartVersion)
	fpath := path.Join(packageDir, fname)
	return fpath
}

func GetHelmPackageURL(chartName, chartVersion string) string {
	chartBaseUrl := FindChartRepo(chartName, chartVersion)
	url := fmt.Sprintf("%s/%s-%s.tgz", chartBaseUrl, chartName, chartVersion)
	return url
}

func GetHelmProvURL(chartName, chartVersion string) string {
	chartBaseUrl := FindChartRepo(chartName, chartVersion)
	url := fmt.Sprintf("%s/%s-%s.tgz.prov", chartBaseUrl, chartName, chartVersion)
	return url
}

func DownloadFile(url, fpath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New(fmt.Sprintf("Received response is not 200 to access %s", url))
	}

	// Create the file
	out, err := os.Create(fpath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}
	return nil
}

func FindChartRepo(chartName, chartVer string) string {
	return os.Getenv("CHART_BASE_URL")
}

func GetHelmValuesFilePath(chartName, chartVersion string) string {
	packageDir := GetPackageDir()
	fname := fmt.Sprintf("%s-%s-values.yaml", chartName, chartVersion)
	fpath := path.Join(packageDir, fname)
	return fpath
}

func GetHelmValuesSignatureFilePath(chartName, chartVersion string) string {
	packageDir := GetPackageDir()
	fname := fmt.Sprintf("%s-%s-values.yaml.sig", chartName, chartVersion)
	fpath := path.Join(packageDir, fname)
	return fpath
}

func ParseManifest(manifest []byte) []map[string]interface{} {

	r := bytes.NewReader(manifest)

	dec := yaml.NewDecoder(r)
	var t map[string]interface{}
	outputs := []map[string]interface{}{}

	for dec.Decode(&t) == nil {
		//output := t.(map[string]interface{})
		outputs = append(outputs, t)
		t = make(map[string]interface{})
	}
	return outputs
}

func base64decode(str string) string {
	decBytes, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return ""
	}
	dec := string(decBytes)
	return dec
}
