#! /bin/sh
set -e
alias python="poetry run python"
poetry run find . -name '*.py' -exec pyupgrade --py37-plus {} +
python -m black tests aiohomekit
python -m isort -rc tests aiohomekit
python -m black tests aiohomekit --check --diff
python -m flake8 tests aiohomekit
python -m pytest tests
