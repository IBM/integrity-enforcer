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
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

type LoggerConfig struct {
	Level    string
	Format   string
	FileDest string
}

// NOTE: this singleton logger should be used only for simple log messages
// for detail logs while handling a certain request, Handler.Logger should be used instead.
var simpleLogger *log.Logger

func init() {
	simpleLogger = log.New()
	simpleLogger.SetFormatter(&log.JSONFormatter{TimestampFormat: time.RFC3339Nano})
}

// func (self *Logger) GetSessionTraceString() string {
// 	return self.SessionTrace.GetBufferedString()
// }

// func InitSessionLogger(namespace, name, apiVersion, kind, operation string) {
// 	// SessionTrace.Reset()
// 	SessionLogger = ServerLogger.WithFields(log.Fields{
// 		"namespace":  namespace,
// 		"name":       name,
// 		"apiVersion": apiVersion,
// 		"kind":       kind,
// 		"operation":  operation,
// 	})
// }

func NewLogger(conf LoggerConfig) *log.Logger {

	logger := log.New()

	if conf.Format == "json" {
		logger.SetFormatter(&log.JSONFormatter{TimestampFormat: time.RFC3339Nano})
	}

	logLevel := log.InfoLevel
	if conf.Level != "" {
		lvl, err := log.ParseLevel(conf.Level)
		if err != nil {
			logger.Info("Failed to parse log level, using info level")
		} else {
			logLevel = lvl
		}
	}
	logger.SetLevel(logLevel)
	if conf.FileDest != "" {
		file, err := os.OpenFile(conf.FileDest, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640) // NOSONAR
		if err == nil {
			logger.Out = file
		} else {
			logger.Info("Failed to log to file, using default stderr")
		}
	} else {
		logger.Out = os.Stdout
	}
	return logger
}

func GetGreaterLevel(lvStr1, lvStr2 string) string {
	// "error" is the minimum level without fatal crash, so this function returns it in case of no custom level
	if lvStr1 == "" {
		lvStr1 = "error"
	}
	if lvStr2 == "" {
		lvStr2 = "error"
	}
	lv1, err1 := log.ParseLevel(lvStr1)
	lv2, err2 := log.ParseLevel(lvStr2)
	if err1 != nil && err2 != nil {
		return "error"
	}
	if lv1 > lv2 {
		return lv1.String()
	} else {
		return lv2.String()
	}
}

func Panic(args ...interface{}) {
	simpleLogger.Panic(args...)
}

func Fatal(args ...interface{}) {
	simpleLogger.Fatal(args...)
}

func Error(args ...interface{}) {
	simpleLogger.Error(args...)
}

func Warn(args ...interface{}) {
	simpleLogger.Warn(args...)
}

func Info(args ...interface{}) {
	simpleLogger.Info(args...)
}

func Debug(args ...interface{}) {
	simpleLogger.Debug(args...)
}

func Trace(args ...interface{}) {
	simpleLogger.Trace(args...)
}

func WithFields(fields log.Fields) *log.Entry {
	return simpleLogger.WithFields(fields)
}
