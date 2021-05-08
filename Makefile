SOURCES_PY  =$(filter-out $(BUILD_PY),$(wildcard *.py src/*.py src/cuisine/*.py src/cuisine/*/*.py)
SOURCES     =$(SOURCES_PY) $(BUILD_PY)
BUILD       =$(BUILD_PY)
BUILD_PY   :=src/cuisine/api/_impl.py src/cuisine/api/_stub.py
MANIFEST    =$(SOURCES)
VERSION    :=$(shell grep VERSION src/cuisine.py | cut -d '=' -f2  | xargs echo)
PRODUCT    :=MANIFEST doc $(BUILD)
PYTHON     :=python3
OS         :=$(shell )uname -s | tr A-Z a-z)

.PHONY: all doc clean check tests

all: $(PRODUCT)

release: $(PRODUCT)
	git commit -a -m "Release $(VERSION)" ; true
	git tag $(VERSION) ; true
	git push --all ; true
	python setup.py clean sdist register upload

tests:
	PYTHONPATH=src:$(PYTHONPATH) python tests/$(OS)/all.py

clean:
	@rm -rf api/ build dist MANIFEST ; true

check:
	pychecker -100 $(SOURCES)

test:
	python tests/all.py

MANIFEST: $(MANIFEST)
	echo $(MANIFEST) | xargs -n1 | sort | uniq > $@

# # Specific

src/cuisine/api/_stub.py:
	PYTHONPATH=src $(PYTHON) -m cuisine.api -m stub -o "$@"

src/cuisine/api/_impl.py:
	PYTHONPATH=src $(PYTHON) -m cuisine.api -m impl -o "$@"

#EOF
