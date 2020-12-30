# Contributing

## Pull requests

## Testing

### Local install

To create a version of threatspec from the current branch, simple run

```
threatspec$ python setup.py install
```

### Unit testing

Unit tests are done using pytest. You can find the test code in the `tests` directory in this repository.

```
threatspec$ python setup.py test
```

### End to end testing with tox

To perform a full set of tests using BATs for each supported version of python, run the tox command:

```
threatspec$ tox
GLOB sdist-make: threatspec/setup.py
py36 inst-nodeps: threatspec/.tox/.tmp/package/1/threatspec-0.5.1.dev7+g11c91f8.zip
py36 installed: atomicwrites==1.3.0,attrs==19.1.0,Click==7.0,comment-parser==1.1.2,graphviz==0.12,importlib-metadata==0.19,Jinja2==2.10.1,jsonschema==3.0.2,MarkupSafe==1.1.1,more-itertools==7.2.0,numpy==1.17.0,packaging==19.1,pandas==0.25.1,pkg-resources==0.0.0,pluggy==0.12.0,py==1.8.0,pyparsing==2.4.2,pyrsistent==0.15.4,pytest==5.1.1,python-dateutil==2.8.0,python-magic==0.4.15,pytz==2019.2,PyYAML==5.1.2,six==1.12.0,threatspec==0.5.1.dev7+g11c91f8,wcwidth==0.1.7,zipp==0.5.2
py36 run-test-pre: PYTHONHASHSEED='3710368835'
py36 run-test: commands[0] | pytest
=============================================================== test session starts ===============================================================
platform linux -- Python 3.6.8, pytest-5.1.1, py-1.8.0, pluggy-0.12.0
...
```

CLI test files can be found in the `cli_tests` directory.

A quick CLI test using the local version can be done using the following command:

```
export TERM=linux; bats cli_tests
```

## Code of Conduct
