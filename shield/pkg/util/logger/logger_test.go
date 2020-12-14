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
	"testing"
)

var logConfig LoggerConfig
var ctxLogConfig ContextLoggerConfig

func init() {
	defaultFormat := "json"
	defaultLogOutput := "" // console
	defaultFilePath := "./test-events.txt"
	defaultRotateSize := int64(10485760) // 10MB
	logConfig = LoggerConfig{Level: "info", Format: defaultFormat, FileDest: defaultLogOutput}
	ctxLogConfig = ContextLoggerConfig{Enabled: true, File: defaultFilePath, LimitSize: defaultRotateSize}
}

func TestLogger(t *testing.T) {
	InitServerLogger(logConfig)
	InitSessionLogger("test-ns", "test-cm", "v1", "ConfigMap", "CREATE")
	InitContextLogger(ctxLogConfig)

	ctxLogger := GetContextLogger()
	_ = GetServerLogger()
	_ = GetSessionLogger()

	Error("test error")
	Warn("test warn")
	Info("test info")
	Debug("test debug")
	Trace("test trace")

	sessionLogs := GetSessionTraceString()
	t.Logf("sessionLogs: %s", sessionLogs)

	ctxLogger.SendLog([]byte(`this is test context log`))
	ctxLogger.sizeCheckAndRotate()
}
