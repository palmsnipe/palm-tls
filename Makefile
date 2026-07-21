SHELL := /bin/bash

.PHONY: all prerequisites bootstrap http tls examples tls-tester check clean

all: check

prerequisites:
	@scripts/prerequisites.sh

bootstrap: prerequisites
	@scripts/bootstrap.sh

http: prerequisites
	@$(MAKE) -C libs/palm-http test

tls: bootstrap
	@$(MAKE) -C libs/palm-tls test

examples: prerequisites
	@$(MAKE) -C examples/network test

tls-tester: bootstrap
	@$(MAKE) -C examples/tls-tester test

check: bootstrap
	@scripts/check.sh

clean:
	@$(MAKE) -C libs/palm-http clean
	@$(MAKE) -C libs/palm-tls clean
	@$(MAKE) -C examples/network clean
	@$(MAKE) -C examples/tls-tester clean
