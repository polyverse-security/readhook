#!/bin/bash

# Delete the old artifacts
rm -r app dll lib obj

# Make the output directories
mkdir -p app dll lib obj

# Remove the build container (if it was left around)
docker rm -f readhook

# Build readhook
docker build -t readhook .

# Run readhook and just sleep while we copy the build artifacts
docker run --name readhook readhook

# Extract the build artifacts
docker cp readhook:/readhook/app .
docker cp readhook:/readhook/dll .
docker cp readhook:/readhook/lib .
docker cp readhook:/readhook/obj .

# Remove the build container
docker rm -f readhook

# Here and below added for jitrop branch
declare -r PV_DOCKER_REGISTRY="507760724064.dkr.ecr.us-west-2.amazonaws.com"
declare -r PV_ANNOTATOR=${PV_DOCKER_REGISTRY}/pe-binary-scrambler:17f8e7-8f6ad7

# Use the container itself to clean up /tmp (Because I don't have privilege to do it!)
docker run -v /tmp/output:/output --entrypoint /bin/bash ${PV_ANNOTATOR} -c 'rm -rf /output/*'

# Annotate the executable
docker run -v $PWD/dll:/input -v /tmp/output:/output -e FILE_TO_SCRAMBLE=basehook.so --rm -it ${PV_ANNOTATOR}

# Combine the annotation artifacts with the original artifacts (overwriting librandomizer.so)
cp -f /tmp/output/scrambled/* $PWD/dll
