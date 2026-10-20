.PHONY: all build test dashboard clean

all: build test

build:
	$(MAKE) -C sdks/c
	$(MAKE) -C sdks/cpp

test: build
	python3 tests/run_all_tests.py

dashboard: build
	node dashboard/server.js

clean:
	$(MAKE) -C sdks/c clean
	$(MAKE) -C sdks/cpp clean
