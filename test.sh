#!/bin/bash

hostport="${1:-docker.for.mac.localhost:5555}"

docker run -it --rm --name readhook -p 5555:5555 readhook /readhook/app/fullhook "$hostport"
