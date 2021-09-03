SHELL = /bin/bash

FIND	= $(shell type -P find)
RM	= $(shell type -P rm)
PYTHON	= $(shell type -P python)
TWINE	= $(shell type -P twine)
XARGS	= $(shell type -P xargs)

PACKAGE_NAME = fake-httpd

.PHONY: all
all:
	@$(PYTHON) -m build

.PHONY: upload
upload:
	@$(TWINE) upload --repository $(PACKAGE_NAME) dist/*

.PHONY: clean
clean:
	@$(FIND) . -type d -name __pycache__ -print0 |$(XARGS) -0 $(RM) -rf
	@$(RM) -rf src/$(PACKAGE_NAME).egg-info

.PHONY: distclean
distclean: clean
	@$(RM) -rf dist

##
# vim: ts=8 sw=8 tw=100 noet fdm=marker :
##
