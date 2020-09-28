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

package cache

import (
	"sync"
	"time"
)

const defaultCacheDuration = time.Second * 5

var cache *Cache

type CachedObject struct {
	rawObject interface{}
	created   time.Time
	expired   time.Time
	duration  time.Duration
}

type Cache struct {
	data map[string]*CachedObject
	mu   sync.RWMutex
}

func init() {
	cache = NewCache()
}

func NewCache() *Cache {
	data := make(map[string]*CachedObject)
	return &Cache{
		data: data,
	}
}

func NewCachedObject(object interface{}, now time.Time, ttl *time.Duration) *CachedObject {
	duration := defaultCacheDuration
	if ttl != nil {
		duration = *ttl
	}
	exp := now.Add(duration)
	return &CachedObject{
		rawObject: object,
		created:   now,
		expired:   exp,
		duration:  duration,
	}
}

func (self *CachedObject) IsExpired() bool {
	now := time.Now()
	return now.After(self.expired)
}

func deleteKey(m map[string]*CachedObject, delKeys []string) map[string]*CachedObject {
	n := make(map[string]*CachedObject)
	delKeyDict := make(map[string]bool)
	for _, delKey := range delKeys {
		delKeyDict[delKey] = true
	}
	for key, val := range m {
		if delKeyDict[key] {
			continue
		}
		n[key] = val
	}
	return n
}

func (self *Cache) clearExpiredItem() {
	delKeys := []string{}
	for key, val := range self.data {
		if val.IsExpired() {
			delKeys = append(delKeys, key)
		}
	}
	self.data = deleteKey(self.data, delKeys)
}

func (self *Cache) Set(name string, object interface{}, ttl *time.Duration) {
	self.mu.Lock()
	self.clearExpiredItem()

	now := time.Now()
	obj := NewCachedObject(object, now, ttl)
	self.data[name] = obj
	self.mu.Unlock()
}

func (self *Cache) Get(name string) interface{} {
	self.mu.RLock()
	now := time.Now()
	obj, ok := self.data[name]
	self.mu.RUnlock()
	if !ok {
		return nil
	}
	if now.After(obj.expired) {
		return nil
	}
	return obj.rawObject
}

func (self *Cache) GetString(name string) string {
	obj := self.Get(name)
	if obj == nil {
		return ""
	}
	objStr, ok := obj.(string)
	if !ok {
		return ""
	}
	return objStr
}

func Set(name string, object interface{}, ttl *time.Duration) {
	cache.Set(name, object, ttl)
}

func SetString(name string, object string, ttl *time.Duration) {
	cache.Set(name, object, ttl)
}

func Get(name string) interface{} {
	return cache.Get(name)
}

func GetString(name string) string {
	return cache.GetString(name)
}
