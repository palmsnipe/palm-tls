SHELL := /bin/bash

.PHONY: all prerequisites bootstrap http tls examples tls-tester check clean

all: check

prerequisites:
	@scripts/prerequisites.sh

bootstrap: prerequisites
	@scripts/bootstrap.sh

http: prerequisites
	@$(MAKE) -C components/http test

tls: bootstrap
	@$(MAKE) -C library test

examples: prerequisites
	@$(MAKE) -C examples/network test

tls-tester: bootstrap
	@$(MAKE) -C apps/tls-tester test

check: bootstrap
	@scripts/check.sh

clean:
	@$(MAKE) -C components/http clean
	@$(MAKE) -C library clean
	@$(MAKE) -C examples/network clean
	@$(MAKE) -C apps/tls-tester clean
