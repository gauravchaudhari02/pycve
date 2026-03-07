# Contributing to PyCVE

Thank you for your interest in contributing! All contributions — bug reports, feature requests, documentation improvements, and code — are welcome.

## Getting Started

1. **Fork** the repository and clone your fork:
   ```bash
   git clone https://github.com/gauravchaudhari02/pycve.git
   cd pycve
   ```

2. **Create a virtual environment** and install dev dependencies:
   ```bash
   # pip
   pip install -e ".[dev]"

   # uv (recommended)
   uv sync --all-extras
   ```

3. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Workflow

### Running Tests
```bash
pytest
```

### Code Style
This project uses `ruff` for linting (line length 100, target Python 3.10).
```bash
pip install ruff
ruff check .
ruff format .
```

### Making Changes

- Keep changes focused — one feature or fix per PR.
- Add or update tests for any code you change.
- Update `CHANGELOG.md` under the `[Unreleased]` section.
- Make sure `pytest` passes before opening a PR.

## Submitting a Pull Request

1. Push your branch to your fork.
2. Open a Pull Request against the `main` branch of this repository.
3. Fill in the PR description — what changed and why.
4. A maintainer will review your PR, suggest changes if needed, and merge it.

## Reporting Bugs

Open an issue on GitHub with:
- A clear title and description.
- Steps to reproduce the problem.
- Expected vs. actual behavior.
- Python version and `pycve` version (`python -c "import pycve; print(pycve.__version__)"`).

## Feature Requests

Open an issue with the `enhancement` label. Describe the use case and the proposed API if applicable.

## Code of Conduct

Be respectful and constructive. Harassment of any kind will not be tolerated.

## License

By contributing you agree that your contributions will be licensed under the [MIT License](LICENSE).
