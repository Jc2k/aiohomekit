#! sh
set -e

python -m black tests aiohomekit
python -m isort -rc tests aiohomekit
python -m black tests aiohomekit --check --diff
python -m flake8 tests aiohomekit
python -m pytest tests
