Every contribution are welcomed as long as few rules are followed.

# TL;DR

- Branch off `devel`.
- Only one feature per commit.
- In case of changes request, amend your commit to avoid multiple commits.
- Run `pylint` before and after coding and take care not to lower the rating.
- Write unit tests as much as possible so we can easily check your code.

# How to contribute

- If you're thinking about a new feature, see if there's already an issue open
about it or please open one otherwise.
- One commit per feature.
- Branch off the `devel` branch.
- Test your code with unit tests.
- Run `pylint` before and after coding and take care not to lower the rating.
It worth mentioning you can freely improve the rating !
- If we ask for a few changes, please amend your commit rather than creting new
commits.
- Remember to be `Python 2.7` compliant.

# How to start coding ?

First thing to do is to install dev requirements by running `pip install -r
requirements/dev.txt`. Everything you need to start coding should be setup.
To be sure everything went ok, run unit tests via `python manage.py test`.

# Branches

- `master` still contains a stable version of the code. Releases are tagged
from this branch.
- `devel` contains all changes in the current development version. Don't use
this code in production since it might break it.

# Licensing for new files

`cerberus-core` is licensed under (modified) BSD license. Anything
contributed to `cerberus-core` must be released under this license.

When introducing a new file into the project, please make sur it has a
copyright header making clear under which licenses it's being released.
