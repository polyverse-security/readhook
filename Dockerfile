FROM	ubuntu:xenial

# This will only do something on alpine (which doesn't come with bash because THAT'S a good idea)
RUN	apk add bash 2>/dev/null || true
	
# We'll be working in a copy of ./readhook
WORKDIR	/readhook
COPY	readhook /readhook

# Install necessary tools for building readhook
RUN     /readhook/setup.sh

# Make sure these output folders exist
RUN	mkdir -p app dll lib obj

# Build it
RUN	make clean all
