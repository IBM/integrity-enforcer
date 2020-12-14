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

package common

import (
	"math/big"
	"testing"
)

func TestPattern(t *testing.T) {
	if !MatchPattern("test-*,test-1,test-2", "test-value") {
		t.Errorf("TestPattern() Failed")
	}
	union := GetUnionOfArrays([]string{"test-*", "test-1", "test-2"}, []string{"test-value"})
	if len(union) != 4 {
		t.Errorf("TestPattern() Failed")
	}

	ok := MatchBigInt("awrg", big.NewInt(1234))
	if ok {
		t.Errorf("TestPattern() Failed")
	}
}
