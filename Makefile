.PHONY: install test build lint clean

install:
	python3 -m venv .venv
	. .venv/bin/activate && pip install -U pip && pip install -e .[dev]

test:
	. .venv/bin/activate && pytest -q

build:
	. .venv/bin/activate && python -m build

lint:
	. .venv/bin/activate && ruff check .

clean:
	rm -rf .venv build dist .pytest_cache .ruff_cache *.egg-info tests/__pycache__
