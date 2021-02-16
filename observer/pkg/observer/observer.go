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

package observer

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"time"

	kubeutil "github.com/IBM/integrity-enforcer/shield/pkg/util/kubeutil"
	"github.com/hpcloud/tail"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const defaultIntervalSecondsStr = "30"
const defaultSummaryConfigMapName = "integrity-shield-status-report"
const timeFormat = "2006-01-02 15:04:05"

type IntegrityShieldObserver struct {
	IShiledNamespace string
	ShieldConfigName string
	EventsFilePath   string
	IntervalSeconds  uint64

	loader     *Loader
	logger     *log.Logger
	eventQueue []string
}

func NewIntegrityShieldObserver(logger *log.Logger) *IntegrityShieldObserver {
	iShieldNS := os.Getenv("SHIELD_NS")
	shieldConfigName := os.Getenv("SHIELD_CONFIG_NAME")
	eventsFilePath := os.Getenv("EVENTS_FILE_PATH")
	intervalSecondsStr := os.Getenv("INTERVAL_SECONDS")
	if intervalSecondsStr == "" {
		intervalSecondsStr = defaultIntervalSecondsStr
	}
	intervalSeconds, err := strconv.ParseUint(intervalSecondsStr, 10, 64)
	if err != nil {
		logger.Warningf("Failed to parse interval seconds `%s`; use default value: %s", intervalSecondsStr, defaultIntervalSecondsStr)
		intervalSeconds, _ = strconv.ParseUint(defaultIntervalSecondsStr, 10, 64)
	}

	loader := NewLoader(iShieldNS, shieldConfigName)

	return &IntegrityShieldObserver{
		IShiledNamespace: iShieldNS,
		ShieldConfigName: shieldConfigName,
		EventsFilePath:   eventsFilePath,
		IntervalSeconds:  intervalSeconds,
		loader:           loader,
		logger:           logger,
	}
}

func (self *IntegrityShieldObserver) Run(event chan *tail.Line, report chan bool) error {
	for {
		var l *tail.Line
		select {
		case l = <-event:
			self.addEvent(l.Text)
		case <-report:
			lines := self.getEvents()
			err := self.report(lines)
			if err != nil {
				return err
			}
		}
	}
}

func (self *IntegrityShieldObserver) report(lines []string) error {
	data, err := self.loader.Load()
	if err != nil {
		self.logger.Errorf("Failed to load IShield Resources; %s", err.Error())
		return err
	}
	events, err := readEventLines(lines)
	if err != nil {
		self.logger.Errorf("Failed to load events.txt; %s", err.Error())
		return err
	}
	err = self.updateSummary(data, events)
	if err != nil {
		self.logger.Errorf("Failed to create or update `%s`; %s", defaultSummaryConfigMapName, err.Error())
		return err
	}
	self.logger.Info("Updated a status report")
	return nil
}

func (self *IntegrityShieldObserver) addEvent(line string) {
	self.eventQueue = append(self.eventQueue, line)
}

func (self *IntegrityShieldObserver) getEvents() []string {
	lines := []string{}
	for _, l := range self.eventQueue {
		lines = append(lines, l)
	}
	self.clearEvents()
	return lines
}

func (self *IntegrityShieldObserver) clearEvents() {
	self.eventQueue = []string{}
}

func readEventLines(lines []string) ([]map[string]interface{}, error) {
	events := []map[string]interface{}{}
	for _, l := range lines {
		var tmpEvent map[string]interface{}
		err := json.Unmarshal([]byte(l), &tmpEvent)
		if err != nil {
			continue
		}
		events = append(events, tmpEvent)
	}
	return events, nil
}

func readEventsFile(fpath string) ([]map[string]interface{}, error) {
	f, err := os.Open(fpath)
	if err != nil {
		return nil, err
	}
	s := bufio.NewScanner(f)
	lines := []string{}
	for s.Scan() {
		lines = append(lines, s.Text())
	}
	return readEventLines(lines)
}

func (self *IntegrityShieldObserver) summarize(data *RuntimeData, events []map[string]interface{}) map[string]string {
	summary := map[string]string{}

	opPods, svPods := getIShieldPods(data)
	podsStatus := makePodsStatus(opPods, svPods)
	for k, v := range podsStatus {
		summary["pods."+k] = v
	}

	rspNum := len(data.RSPList.Items)
	rsigNum := len(data.ResSigList.Items)

	count := 0
	denyCount := 0
	for _, e := range events {
		allowedIf, ok1 := e["allowed"]
		if !ok1 {
			continue
		}
		allowed, ok2 := allowedIf.(bool)
		if !ok2 {
			continue
		}

		count++
		if !allowed {
			denyCount++
		}
	}
	summary["count.events"] = strconv.Itoa(count)
	summary["count.deniedEvents"] = strconv.Itoa(denyCount)
	summary["resource.numOfRSPs"] = strconv.Itoa(rspNum)
	summary["resource.numOfResSigs"] = strconv.Itoa(rsigNum)
	summary["__meta.interval"] = strconv.Itoa(int(self.IntervalSeconds))
	summary["__meta.updatedTimestamp"] = time.Now().UTC().Format(timeFormat)
	return summary
}

func (self *IntegrityShieldObserver) updateSummary(data *RuntimeData, events []map[string]interface{}) error {

	summary := self.summarize(data, events)

	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		return err
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	cmNS := self.IShiledNamespace
	cmName := defaultSummaryConfigMapName
	cm := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: cmName,
		},
		Data: summary,
	}
	alreadyExists := false
	current, getErr := client.CoreV1().ConfigMaps(cmNS).Get(context.Background(), cmName, metav1.GetOptions{})
	if current != nil && getErr == nil {
		alreadyExists = true
		cm = current
		cm.Data = summary
	}

	if alreadyExists {
		_, err = client.CoreV1().ConfigMaps(cmNS).Update(context.Background(), cm, metav1.UpdateOptions{})
	} else {
		_, err = client.CoreV1().ConfigMaps(cmNS).Create(context.Background(), cm, metav1.CreateOptions{})
	}
	if err != nil {
		return err
	}
	return nil
}

func getIShieldPods(data *RuntimeData) ([]v1.Pod, []v1.Pod) {
	operatorDeployName := ""
	serverDeployName := ""
	operatorPods := []v1.Pod{}
	serverPods := []v1.Pod{}
	for _, ores := range data.ShieldConfig.Spec.ShieldConfig.IShieldResourceCondition.OperatorResources {
		if ores.Kind == "Deployment" {
			operatorDeployName = ores.Name
			break
		}
	}
	for _, sres := range data.ShieldConfig.Spec.ShieldConfig.IShieldResourceCondition.ServerResources {
		if sres.Kind == "Deployment" {
			serverDeployName = sres.Name
			break
		}
	}
	for _, pod := range data.PodList.Items {
		podName := pod.GetName()
		if strings.HasPrefix(podName, operatorDeployName) {
			operatorPods = append(operatorPods, pod)
		}
		if strings.HasPrefix(podName, serverDeployName) {
			serverPods = append(serverPods, pod)
		}
	}
	return operatorPods, serverPods
}

type ContainerStatus struct {
	Name         string            `json:"name"`
	State        v1.ContainerState `json:"state"`
	LastState    v1.ContainerState `json:"lastState"`
	RestartCount int32             `json:"restartCount"`
	Ready        bool              `json:"ready"`
}

func makePodsStatus(opPods, svPods []v1.Pod) map[string]string {
	s := map[string]string{}
	for _, pod := range opPods {
		podName := pod.GetName()
		podStatus := []ContainerStatus{}
		for _, status := range pod.Status.ContainerStatuses {
			tmpStatus := ContainerStatus{
				Name:         status.Name,
				State:        status.State,
				LastState:    status.LastTerminationState,
				RestartCount: status.RestartCount,
				Ready:        status.Ready,
			}
			podStatus = append(podStatus, tmpStatus)
		}
		podStatusBytes, _ := json.Marshal(podStatus)
		s[podName] = string(podStatusBytes)
	}
	for _, pod := range svPods {
		podName := pod.GetName()
		podStatus := []ContainerStatus{}
		for _, status := range pod.Status.ContainerStatuses {
			tmpStatus := ContainerStatus{
				Name:         status.Name,
				State:        status.State,
				LastState:    status.LastTerminationState,
				RestartCount: status.RestartCount,
				Ready:        status.Ready,
			}
			podStatus = append(podStatus, tmpStatus)
		}
		podStatusBytes, _ := json.Marshal(podStatus)
		s[podName] = string(podStatusBytes)
	}
	return s
}
