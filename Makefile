CD=cd
FIND=find
DEL=rm
PYTHON=python
PIP=pip3.4
COVERAGE=coverage
COVERALLS=coveralls
PYLINT=pylint
SPHINX=sphinx-build

DOC_DIR=doc/build

clean: clean-doc
	$(FIND) . -name __pycache__ | xargs -r $(DEL) -rf
	$(FIND) . -name "*.pyc*" | xargs -r $(DEL)

clean-doc:
	$(DEL) -rf $(DOC_DIR)

install-deps:
	$(PIP) install -r requirements/common.txt

install-dev-deps:
	$(PIP) install -r requirements/dev.txt

test: 
	$(COVERAGE) > /dev/null 2>&1 && \
	$(COVERAGE) run --source='.' manage.py test && \
	$(COVERAGE) report --omit="virtualenv/*,*ovh*,tests/*,manage.py" \
		|| \
	$(PYTHON) manage.py test

coveralls:
	$(COVERAGE) erase && \
	$(COVERAGE) > /dev/null 2>&1 && \
	$(COVERAGE) run --source='.' --omit="virtualenv/*,*ovh*,tests/*,manage.py" manage.py test && \
	$(COVERALLS)

lint:
	$(PYLINT) --load-plugins pylint_django --disable=C0413 --disable=W0141 --disable=W0403 --max-line-length=150 api/ worker/ adapters/ default/

doc: clean-doc
	$(SPHINX) -b html doc/source doc/build

