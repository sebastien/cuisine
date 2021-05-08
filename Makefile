SOURCES_PY  =$(filter-out $(BUILD_PY),$(wildcard *.py src/*.py src/cuisine/*.py src/cuisine/*/*.py))
SOURCES     =$(SOURCES_PY) $(BUILD_PY)
BUILD       =$(BUILD_PY)
BUILD_PY   :=src/cuisine/api/_impl.py src/cuisine/api/_stub.py src/cuisine/api/_repl.py
MANIFEST    =$(SOURCES)
VERSION    :=2.0.0
PRODUCT    :=MANIFEST doc $(BUILD)
PYTHON     :=python3
OS         :=$(shell )uname -s | tr A-Z a-z)

readonly-pre=if [ -e "$1" ]; then chmod +w "$1" ; fi
readonly-post=if [ -e "$1" ]; then chmod -w "$1" ; fi

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

src/cuisine/api/_stub.py: $(filter src/cuisine/api/%,$(SOURCES_PY))
	$(call readonly-pre,$@)
	PYTHONPATH=src $(PYTHON) -m cuisine.api -t stub -o "$@"
	$(call readonly-post,$@)

src/cuisine/api/_impl.py: $(filter src/cuisine/api/%,$(SOURCES_PY))
	$(call readonly-pre,$@)
	PYTHONPATH=src $(PYTHON) -m cuisine.api -t impl -o "$@"
	$(call readonly-post,$@)

src/cuisine/api/_repl.py: $(filter src/cuisine/api/%,$(SOURCES_PY))
	$(call readonly-pre,$@)
	PYTHONPATH=src $(PYTHON) -m cuisine.api -t repl -o "$@"
	$(call readonly-post,$@)



#EOF
