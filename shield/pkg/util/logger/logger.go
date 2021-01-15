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
	"bytes"
	"encoding/json"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

type LoggerConfig struct {
	Level    string
	Format   string
	FileDest string
}

var ServerLoggerLogger *log.Logger
var ServerLogger *log.Entry
var SessionTrace *SessionTraceHook
var SessionLogger *log.Entry

func GetServerLogger() *log.Entry {
	return ServerLogger
}

func GetSessionLogger() *log.Entry {
	return SessionLogger
}

func GetSessionTraceString() string {
	return SessionTrace.GetBufferedString()
}

func InitServerLogger(config LoggerConfig) {
	ServerLoggerLogger = newLogger(config)
	sessionTraceHook := NewSessionTraceHook(logrus.TraceLevel, &log.TextFormatter{})
	SessionTrace = sessionTraceHook
	ServerLoggerLogger.AddHook(sessionTraceHook)
	ServerLogger = ServerLoggerLogger.WithField("loggerUID", uuid.New().String())
}

func InitSessionLogger(namespace, name, apiVersion, kind, operation string) {
	SessionTrace.Reset()
	SessionLogger = ServerLogger.WithFields(log.Fields{
		"namespace":  namespace,
		"name":       name,
		"apiVersion": apiVersion,
		"kind":       kind,
		"operation":  operation,
	})
}

func newLogger(conf LoggerConfig) *log.Logger {

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

func SetLogLevel(levelString string) {
	if levelString != "" {
		level, err := log.ParseLevel(levelString)
		if err != nil {
			ServerLogger.Info("Failed to parse log level, using info level")
		} else {
			ServerLoggerLogger.SetLevel(level)
		}
	}
}

/*
   Hook for Logging to Buffer
*/

type SessionTraceHook struct {
	writer    *bytes.Buffer
	minLevel  logrus.Level
	formatter logrus.Formatter
}

func (hook *SessionTraceHook) Reset() {
	(*hook.writer).Reset()
}

func (hook *SessionTraceHook) GetBufferedString() string {
	s := (*hook.writer).String()
	hook.Reset()
	return s
}

func NewSessionTraceHook(minLevel logrus.Level, formatter logrus.Formatter) *SessionTraceHook {
	return &SessionTraceHook{
		writer:    &bytes.Buffer{},
		minLevel:  minLevel,
		formatter: formatter,
	}
}

func (hook *SessionTraceHook) Fire(entry *logrus.Entry) error {

	msg, err := hook.formatter.Format(entry)
	if err != nil {
		return err
	}

	if hook.writer != nil {
		_, err = (*hook.writer).Write([]byte(msg))
	}
	return err
}

func (hook *SessionTraceHook) Levels() []logrus.Level {
	return logrus.AllLevels[:hook.minLevel+1]
}

func Panic(args ...interface{}) {
	ServerLogger.Panic(args...)
}

func Fatal(args ...interface{}) {
	ServerLogger.Fatal(args...)
}

func Error(args ...interface{}) {
	ServerLogger.Error(args...)
}

func Warn(args ...interface{}) {
	ServerLogger.Warn(args...)
}

func Info(args ...interface{}) {
	ServerLogger.Info(args...)
}

func Debug(args ...interface{}) {
	ServerLogger.Debug(args...)
}

func Trace(args ...interface{}) {
	ServerLogger.Trace(args...)
}

func WithFields(fields log.Fields) *log.Entry {
	return ServerLogger.WithFields(fields)
}

func AddValueToListField(key, val string) {
	data := map[string]interface{}(ServerLogger.Data)
	current := data[key]
	if current == nil {
		current = "[]"
	}
	currentStr, ok := current.(string)
	if !ok {
		current = "[]"
	}
	var currentList []string
	err := json.Unmarshal([]byte(currentStr), &currentList)
	if err != nil {
		currentList = []string{}
	}
	currentList = append(currentList, val)
	newStr, err := json.Marshal(currentList)
	if err != nil {
		newStr = []byte("[]")
	}
	ServerLogger = ServerLogger.WithFields(log.Fields{key: string(newStr)})
}

func RemoveValueFromListField(key, val string) {
	data := map[string]interface{}(ServerLogger.Data)
	current := data[key]
	if current == nil {
		current = "[]"
	}
	currentStr, ok := current.(string)
	if !ok {
		current = "[]"
	}
	var currentList []string
	err := json.Unmarshal([]byte(currentStr), &currentList)
	if err != nil {
		currentList = []string{}
	}
	newList := []string{}
	for _, v := range currentList {
		if v != val {
			newList = append(newList, v)
		}
	}
	newStr, err := json.Marshal(newList)
	if err != nil {
		newStr = []byte("[]")
	}
	ServerLogger = ServerLogger.WithFields(log.Fields{key: string(newStr)})
}
