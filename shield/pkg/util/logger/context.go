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

package logger

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
)

type ContextLoggerConfig struct {
	Enabled   bool
	File      string
	LimitSize int64
}

type ContextLogger struct {
	enabled   bool
	file      string
	limitSize int64
}

func InitContextLogger(config ContextLoggerConfig) *ContextLogger {
	contextLogger := &ContextLogger{
		enabled:   config.Enabled,
		file:      config.File,
		limitSize: config.LimitSize,
	}
	return contextLogger
}

func (cxLogger *ContextLogger) sizeCheckAndRotate() error {
	f, err := os.OpenFile(cxLogger.file, os.O_CREATE|os.O_WRONLY, 0640) // NOSONAR
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()

	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if fi.Size() > cxLogger.limitSize {
		err := os.Remove(cxLogger.file)
		if err != nil {
			return err
		}
	}
	return nil
}

func (cxLogger *ContextLogger) writeToFile(logBytes []byte) error {
	err := cxLogger.sizeCheckAndRotate()
	if err != nil {
		return err
	}

	f, err := os.OpenFile(cxLogger.file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640) // NOSONAR
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()

	line := fmt.Sprintf("%s\n", string(logBytes))
	if _, err := f.WriteString(line); err != nil {
		return err
	}
	return nil
}

func (cxLogger *ContextLogger) SendLog(logBytes []byte) {
	if !cxLogger.enabled {
		return
	}

	err := cxLogger.writeToFile(logBytes)
	if err != nil {
		simpleLogger.WithFields(log.Fields{
			"err": err,
		}).Debug("Context log file dump err")
		return
	}

}
