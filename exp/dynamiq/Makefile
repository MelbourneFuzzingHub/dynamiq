IMAGE ?= dynamiq
TAG ?= latest
DOCKER ?= docker

.PHONY: image shell check

image:
	$(DOCKER) build \
		-t $(IMAGE):$(TAG) \
		-f Dockerfile ../..

shell:
	./run-in-docker.sh bash

check:
	./run-in-docker.sh bash -lc 'python3 -m py_compile /dynamiq/DynamiQ.py && test -x /opt/dynamiq-fuzzers/target/release/parallel_sync'
