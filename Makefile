SOURCES     = $(wildcard src/*.py)
DOC_SOURCES = $(wildcard docs/* docs/*/*)
MANIFEST    = $(SOURCES) $(wildcard *.py api/*.* AUTHORS* README* LICENSE*)
VERSION     = `grep VERSION src/cuisine.py | cut -d '=' -f2  | xargs echo`
PRODUCT     = MANIFEST doc
OS          = `uname -s | tr A-Z a-z`

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

#EOF
