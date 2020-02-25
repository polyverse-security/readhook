#!/bin/bash

# Delete the old artifacts
rm -r app dll lib obj

# Make the output directories
mkdir -p app dll lib obj

# Remove the build container (if it was left around)
docker rm -f readhook

# Build readhook
docker build --no-cache -t readhook .

# Run readhook and just sleep while we copy the build artifacts
docker run --name readhook readhook

# Extract the build artifacts
docker cp readhook:/readhook/app/ $PWD/app/
docker cp readhook:/readhook/dll/ $PWD/dll/
docker cp readhook:/readhook/lib/ $PWD/lib/
docker cp readhook:/readhook/obj/ $PWD/obj/

# Remove the build container
docker rm -f readhook
