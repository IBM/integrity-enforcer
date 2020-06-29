#
# Copyright 2020 IBM Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#!/bin/bash

echo "fluentd will start in 10 seconds."
sleep 10

mode="none"
if [[ $STDOUT_ENABLED == "true" ]]; then
    if [[ $ES_ENABLED == "true" ]]; then
        mode="std_es"
    else
        mode="std"
    fi
else
    if [[ $ES_ENABLED == "true" ]]; then
        mode="es"
    else
        mode="none"
    fi
fi

if [[ $mode == "none" ]]; then
    echo "logging does not output anything in this configuration..."
fi

fluentd -c ./fluent_${mode}.conf --no-supervisor

