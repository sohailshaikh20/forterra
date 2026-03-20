.PHONY: setup install dev test lint clean build publish

# First-time setup
setup:
	python -m venv venv
	. venv/bin/activate && pip install -e ".[dev]"
	@echo ""
	@echo "✅ Setup complete! Run: source venv/bin/activate"

# Install for development (editable mode)
dev:
	pip install -e ".[dev]"

# Install normally
install:
	pip install .

# Run tests
test:
	pytest tests/ -v --cov=forterra

# Lint code
lint:
	ruff check forterra/
	black --check forterra/

# Format code
format:
	black forterra/
	ruff check --fix forterra/

# Clean build artifacts
clean:
	rm -rf dist/ build/ *.egg-info __pycache__ .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} +

# Build package for PyPI
build: clean
	python -m build

# Publish to PyPI (you'll need a PyPI account)
publish: build
	python -m twine upload dist/*

# Publish to Test PyPI first (for testing)
publish-test: build
	python -m twine upload --repository testpypi dist/*
