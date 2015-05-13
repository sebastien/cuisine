SOURCES     = $(wildcard src/*.py)
DOC_SOURCES = $(wildcard docs/* docs/*/*)
MANIFEST    = $(SOURCES) $(wildcard *.py api/*.* AUTHORS* README* LICENSE*)
VERSION     = `grep VERSION src/cuisine.py | cut -d '=' -f2  | xargs echo`
PRODUCT     = MANIFEST doc
OS          = `uname -s | tr A-Z a-z`

.PHONY: all doc clean check tests

all: $(PRODUCT)

release: $(PRODUCT)
	git commit -a -m "Release $(VERSION)"
	git tag $(VERSION) ; true
	git push --all ; true
	python setup.py clean sdist register upload

tests:
	PYTHONPATH=src:$(PYTHONPATH) python tests/$(OS)/all.py

clean:
	@rm -rf api/ build dist MANIFEST ; true
	vagrant destroy -f

check:
	pychecker -100 $(SOURCES)

doc: $(DOC_SOURCES)
	#sphinx-build -b html docs api
	sdoc         --markup=texto src/cuisine.py api/cuisine-api.html

test:
	python tests/all.py

up:
	vagrant up --no-provision --provider virtualbox

provision:
	vagrant provision

MANIFEST: $(MANIFEST)
	echo $(MANIFEST) | xargs -n1 | sort | uniq > $@

#EOF
