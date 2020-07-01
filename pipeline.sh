#!/bin/bash
set -e
export AWS_ACCESS_KEY_ID="dummy" # For some reason, everything breaks down if an access key and secret access key are not present
export AWS_SECRET_ACCESS_KEY="value" # Using fake values fixes the problem without exposing any security concerns...
npm install
npm i -g serverless
sls dynamodb install
TMPFILE=./offline$$.log
sls offline start 2>1 > $TMPFILE &
PID=$!
echo $PID > .offline.pid
while ! grep "server ready" $TMPFILE
do sleep 1; done
rm $TMPFILE
echo "Starting tests..."
npm test
