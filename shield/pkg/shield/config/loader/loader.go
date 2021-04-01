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

package loader

import (
	"context"
	"os"
	"strconv"
	"time"

	ecfgclient "github.com/IBM/integrity-enforcer/shield/pkg/client/shieldconfig/clientset/versioned/typed/shieldconfig/v1alpha1"
	sconfig "github.com/IBM/integrity-enforcer/shield/pkg/shield/config"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

type Config struct {
	ShieldConfig *sconfig.ShieldConfig
	lastUpdated  time.Time
}

func NewConfig() *Config {
	config := &Config{}
	return config
}

func (conf *Config) InitShieldConfig() bool {

	renew := false
	t := time.Now()
	if conf.ShieldConfig != nil {

		interval := 20
		if s := os.Getenv("SHIELD_CM_RELOAD_SEC"); s != "" {
			if v, err := strconv.Atoi(s); err != nil {
				interval = v
			}
		}

		duration := t.Sub(conf.lastUpdated)
		if int(duration.Seconds()) > interval {
			renew = true
		}
	} else {
		renew = true
	}

	if renew {
		shieldNs := os.Getenv("SHIELD_NS")
		shieldConfigName := os.Getenv("SHIELD_CONFIG_NAME")
		shieldConfig := LoadShieldConfig(shieldNs, shieldConfigName)
		if shieldConfig == nil {
			if conf.ShieldConfig == nil {
				log.Fatal("Failed to initialize ShieldConfig. Exiting...")
			} else {
				shieldConfig = conf.ShieldConfig
				log.Warn("The loaded ShieldConfig is nil, re-use the existing one.")
			}
		}

		chartRepo := os.Getenv("CHART_BASE_URL")
		if chartRepo == "" {
			chartRepo = ""
		}

		if shieldConfig != nil {
			shieldConfig.ChartRepo = chartRepo
			conf.ShieldConfig = shieldConfig
			conf.lastUpdated = t
		}
	}

	return renew
}

func LoadShieldConfig(namespace, cmname string) *sconfig.ShieldConfig {

	config, err := rest.InClusterConfig()
	if err != nil {
		return nil
	}
	clientset, err := ecfgclient.NewForConfig(config)
	if err != nil {
		log.Error(err)
		return nil
	}
	ecres, err := clientset.ShieldConfigs(namespace).Get(context.Background(), cmname, metav1.GetOptions{})
	if err != nil {
		log.Error("failed to get ShieldConfig:", err.Error())
		return nil
	}

	ec := ecres.Spec.ShieldConfig
	return ec
}
