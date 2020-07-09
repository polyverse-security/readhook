#!/bin/bash
set -e

docker build -t readhook .

# Run it with $PWD/src mounted to /readhook
docker run -it -v $PWD/readhook:/readhook -w /readhook readhook bash
