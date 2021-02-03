#!/bin/bash

logs=$(ls ${SHIELD_OP_DIR}test/e2e/*.log 2>/dev/null | wc -l)

if [ ! $logs = 0 ]; then
   echo logs: $logs
   sudo rm ${SHIELD_OP_DIR}test/e2e/*.log
fi
