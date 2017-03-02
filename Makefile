CD=cd
FIND=find
DEL=rm
PYTHON=python
TAR=tar
PIP=pip3.4
COVERAGE=coverage
COVERALLS=coveralls
PYLINT=pylint
SPHINX=sphinx-build

DOC_DIR=doc/build

clean: clean-doc
	if [[ `$(FIND) . -name *.pyc` ]] ; \
	then \
		$(FIND) . -name *.pyc | xargs -r $(DEL) ; \
	fi;

clean-doc:
	$(DEL) -rf $(DOC_DIR)

install-deps:
	$(PIP) install -r requirements.txt

install-dev-deps:
	$(PIP) install -r requirements/dev.txt

test: 
	$(COVERAGE) > /dev/null 2>&1 && \
	$(COVERAGE) run --source='.' manage.py test && \
	$(COVERAGE) report --omit="virtualenv/*,*ovh*,tests/*,tests_ovh/*,docker/*,doc/*,manage.py" \
		|| \
	$(PYTHON) manage.py test

coveralls:
	$(COVERAGE) erase && \
	$(COVERAGE) > /dev/null 2>&1 && \
	$(COVERAGE) run --source='.' --omit="virtualenv/*,*ovh*,tests/*,manage.py" manage.py test && \
	$(COVERALLS)

lint:
	$(PYLINT) --load-plugins pylint_django --disable=C0413 --disable=W0141 --disable=W0403 --max-line-length=100 api/ worker/ adapters/ default/ utils/ event/ /factory

doc: clean-doc
	$(SPHINX) -b html doc/source doc/build

dist: clean-doc
	$(TAR) --exclude='./docker' -cvzf cerberus-core.tgz .
