
@mypy:
  uv run python3 -m mypy --config=pyproject.toml certpeek.py

@black:
  uv run python3 -m black --config=pyproject.toml certpeek.py

@isort:
  uv run python3 -m isort --settings-file=pyproject.toml certpeek.py

@checks: black isort mypy

@updatectlogs:
  uv run ./updatectlogs.py
