SOURCES     = $(wildcard src/*.py)
DOC_SOURCES = $(wildcard docs/* docs/*/*)
MANIFEST    = $(SOURCES) $(wildcard *.py api/*.* AUTHORS* README* LICENSE*)
VERSION     = `grep VERSION src/cuisine.py | cut -d '=' -f2  | xargs echo`
PRODUCT     = MANIFEST doc

.PHONY: all doc clean check
	
all: $(PRODUCT)

release: $(PRODUCT)
	git commit -a -m "Release $(VERSION)"
	git tag $(VERSION) ; true
	git push --all ; true
	python setup.py clean sdist register upload

clean:
	@rm -rf api/ build dist MANIFEST ; true

check:
	pychecker -100 $(SOURCES)

doc: $(DOC_SOURCES)
	#sphinx-build -b html docs api
	sdoc         --markup=texto src/cuisine.py api/cuisine-api.html

MANIFEST: $(MANIFEST)
	echo $(MANIFEST) | xargs -n1 | sort | uniq > $@

#EOF
