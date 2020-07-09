#!/bin/bash

# Remove the build container (if it was left around)
docker rm -f readhook

# Build readhook
docker build -t readhook .

# Run readhook so we can copy artifacts out of it
docker run --name readhook readhook

# Extract the build artifacts
#docker cp readhook:/readhook/app .
#docker cp readhook:/readhook/dll .
#docker cp readhook:/readhook/lib .
#docker cp readhook:/readhook/obj .

# Remove the build container
docker rm -f readhook
