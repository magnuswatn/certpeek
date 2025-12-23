
@ruff:
  uv run ruff format --check && uv run ruff check

@ty:
  uv run ty check

@checks: ruff ty

@updatectlogs:
  uv run ./updatectlogs.py
