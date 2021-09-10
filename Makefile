SHELL = /bin/bash

FIND	= $(shell type -P find)
RM	= $(shell type -P rm)
PYTHON	= $(shell type -P python)
SED	= $(shell type -P sed)
TWINE	= $(shell type -P twine)
XARGS	= $(shell type -P xargs)

include version.mk

PACKAGE_NAME = fake-httpd
PACKAGE_VERSION = $(MAJOR_VERSION).$(MINOR_VERSION).$(PATCH_VERSION)$(EXTRA_VERSION)

ALL_TARGETS = build

.PHONY: all
all: $(ALL_TARGETS)

.PHONY: check
check: check-syntax run-testsuite

.PHONY: check-syntax
check-syntax:
	@if [[ $$(type -P find-python-syntax-errors) ]]; \
	then \
	  echo; \
	  echo "Checking source tree for syntax errors in Python files..."; \
	  echo; \
	  find-python-syntax-errors || exit 1; \
	fi

.PHONY: run-testsuite
run-testsuite:
	@echo "Running test suite..."
	@echo
	@$(PYTHON) setup.py nosetests

.PHONY: build
build: src/fake_httpd/version.py
	@$(PYTHON) -m build

src/fake_httpd/version.py: src/fake_httpd/version.py.in
	@$(SED) \
	  -e 's,@PACKAGE_VERSION@,$(PACKAGE_VERSION),g' \
	  -e 's,@MAJOR_VERSION@,$(MAJOR_VERSION),g' \
	  -e 's,@MINOR_VERSION@,$(MINOR_VERSION),g' \
	  -e 's,@PATCH_VERSION@,$(PATCH_VERSION),g' \
	  -e 's,@EXTRA_VERSION@,$(EXTRA_VERSION),g' \
	  < $< > $@

.PHONY: upload
upload:
	@$(TWINE) upload --repository $(PACKAGE_NAME) dist/*

.PHONY: install
install:
	@$(PYTHON) setup.py install

.PHONY: clean
clean:
	@$(FIND) . -type d -name __pycache__ -print0 |$(XARGS) -0 $(RM) -rf
	@$(RM) -rf src/$(PACKAGE_NAME).egg-info
	@$(RM) -f src/fake_httpd/version.py

.PHONY: distclean
distclean: clean
	@$(RM) -rf dist

##
# vim: ts=8 sw=8 tw=100 noet fdm=marker :
##
