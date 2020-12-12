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
	"testing"
)

func TestCacheFunctions(t *testing.T) {
	NewCache()
	testKeyStr := "testKey"
	testValStr := "testVal"
	testValInt := 4
	SetString(testKeyStr, testValStr, nil)
	val1 := GetString(testKeyStr)
	if val1 != testValStr {
		t.Errorf("\nexpected: %s\nactual: %s", testValStr, val1)
	}
	Unset(testKeyStr)
	val2 := GetString(testKeyStr)
	if val2 != "" {
		t.Errorf("\nexpected: \"\" (empty string)\nactual: %s", val2)
	}

	if KeyExists(testKeyStr) {
		t.Errorf("key `%s` should not exist after unset()", testKeyStr)
	}

	Set(testKeyStr, testValInt, nil)
	valIf := Get(testKeyStr)
	if valInt, ok := valIf.(int); !ok {
		t.Errorf("val for key `%s` should be int", testKeyStr)
	} else if valInt != testValInt {
		t.Errorf("\nexpected: %d\nactual: %d", testValInt, valInt)
	}

}
