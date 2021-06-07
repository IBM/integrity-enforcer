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

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

const defaultImage = "localhost:5000/argocd-builder:latest"
const defaultArgoCDNamespace = "argocd"

const argocdNamespaceEnv = "ARGOCD_NAMESPACE"
const inContainerAppConfigPath = "/tmp/appconfig"

func NewArgocdBuilderCommand() *cobra.Command {

	var imageRef string
	var namespace string
	cmd := &cobra.Command{
		Use:   "argocd-builder",
		Short: "A command to generate YAMLs from ArgoCD Application definition (this is a wrapper of `argocd-builder-core`)",
		RunE: func(cmd *cobra.Command, args []string) error {
			appConfigPath := ""
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}
			if len(args) > 0 {
				appConfigPath = filepath.Clean(filepath.Join(cwd, args[0]))
			} else {
				appConfigPath = cwd
			}
			manifest, err := runCore(appConfigPath, imageRef, namespace)
			if err != nil {
				return err
			}
			fmt.Print(manifest)
			return nil
		},
	}

	cmd.PersistentFlags().StringVarP(&imageRef, "image", "i", defaultImage, "image name in which you execute argocd-buidler-core")
	cmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", defaultArgoCDNamespace, "image name in which you execute argocd-buidler-core")

	return cmd
}

func cmdExec(baseCmd string, args ...string) (string, error) {
	cmd := exec.Command(baseCmd, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return "", errors.Wrap(err, stderr.String())
	}
	out := stdout.String()
	return out, nil
}

func runCore(appConfigDirPath, imageRef, namespace string) (string, error) {

	volumeOption := fmt.Sprintf("%s:%s", appConfigDirPath, inContainerAppConfigPath)
	envOption := fmt.Sprintf("%s=%s", argocdNamespaceEnv, namespace)
	baseCmd := "docker"
	cmdArgs := []string{
		"run",
		"--rm",
		"--name",
		"argocd-builder",
		"--volume",
		volumeOption,
		"--env",
		envOption,
		imageRef,
		"argocd-builder-core",
	}
	// fmt.Println(baseCmd, " ", strings.Join(cmdArgs, " "))
	manifest, err := cmdExec(baseCmd, cmdArgs...)
	if err != nil {
		return "", err
	}
	return manifest, nil
}

func init() {

}

func main() {

	cmd := NewArgocdBuilderCommand()
	cmd.SetOutput(os.Stdout)
	if err := cmd.Execute(); err != nil {
		cmd.SetOutput(os.Stderr)
		cmd.Println(err)
		os.Exit(1)
	}
	os.Exit(0)
}
