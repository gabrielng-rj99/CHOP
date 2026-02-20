# CHOP - Test Suite Documentation

## Overview

This directory contains the complete test suite for the CHOP (Client Hub Open Project). Tests are organized by category and cover:

- **Unit Tests**: Core functionality and business logic
- **Integration Tests**: Component interactions and API endpoints
- **Security Tests**: OWASP Top 10 vulnerabilities, authentication, authorization
- **Block/Lock Tests**: Login blocking system, progressive locks, manual blocks

## Quick Start

### Prerequisites

- Python 3.8+
- pytest
- requests
- PostgreSQL (for integration/security tests)

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run All Tests

```bash
./run_all_tests.sh
```

### Run Specific Test Categories

```bash
# Run only login blocking tests
./run_all_tests.sh -m login_blocking

# Run security tests
./run_all_tests.sh -m security

# Run tests matching a keyword
./run_all_tests.sh -k "test_login"

# Verbose output
./run_all_tests.sh -v

# Generate coverage report
./run_all_tests.sh --coverage

# Generate HTML report
./run_all_tests.sh --html
```

## Test Organization

### Core Test Files

#### `test_login_blocking.py`
Tests for the progressive login blocking system:
- Level 1 block: 3 failed attempts → 5 minute lock
- Level 2 block: 5 failed attempts → 15 minute lock
- Level 3 block: 10 failed attempts → 1 hour lock
- Level 4 block: 15 failed attempts → permanent lock

Tests verify:
- Blocking is applied correctly
- Users cannot login during lock period
- Lock status is visible in API responses
- Manual admin blocking works
- Temporary blocks show countdown timer in frontend

#### `test_block_security.py`
Advanced security tests for blocking system:
- JWT invalidation during blocks
- Refresh token denial
- Privilege escalation attempts
- Block expiration

#### `test_jwt_security.py`
JWT token security:
- Token validation
- Expiration handling
- Token manipulation detection
- Refresh token flow

#### `test_authorization.py`
Authorization and role-based access control:
- User roles (root, admin, user)
- Permission validation
- Privilege escalation prevention

#### `test_security_general.py`
General security validations:
- Input sanitization
- Output encoding
- Error message handling
- Rate limiting

### Security Test Files

- `test_xss_security.py` - Cross-site scripting prevention
- `test_sql_injection.py` - SQL injection protection
- `test_data_leakage.py` - Sensitive data exposure prevention
- `test_bypass_attacks.py` - Authentication bypass attempts
- `test_password_validation.py` - Password strength requirements

### API Test Files

- `test_api_endpoints.py` - General API endpoint testing
- `test_users_api_security.py` - User management endpoints
- `test_clients_api_security.py` - Client endpoints
- `test_contracts_security.py` - Contract endpoints
- `test_financial_security.py` - Financial endpoints
- `test_roles_permissions_security.py` - Role and permission endpoints

## Configuration

### Environment Variables

```bash
# API Base URL (priority: API_URL, then TEST_API_URL, then http://localhost:3000/api)
export API_URL="http://localhost:3000/api"
# Alternative override (same effect if API_URL is not set)
export TEST_API_URL="http://localhost:3000/api"

# Root user password used by tests (defaults to dev.ini)
export TEST_ROOT_PASSWORD="THIS_IS_A_DEV_ENVIRONMENT_PASSWORD!123abc"

# Database connection (for local integration tests)
export DB_HOST="localhost"
export DB_PORT="5432"
export DB_USER="chopuser"
export DB_PASSWORD="password"
export DB_NAME="chopdb_dev"
```

### pytest Markers

Tests are tagged with markers for selective execution:

- `@pytest.mark.security` - Security-related tests
- `@pytest.mark.login_blocking` - Login blocking system tests
- `@pytest.mark.authorization` - Authorization tests
- `@pytest.mark.api` - API endpoint tests
- `@pytest.mark.integration` - Integration tests
- `@pytest.mark.unit` - Unit tests

### conftest.py

Contains shared fixtures and configuration:

- `api_url` - API base URL
- `root_credentials` - Root user credentials
- `root_token` - Authenticated root token
- `test_user` - Test user for tests
- `http_client` - HTTP client with cookies support

## Running Tests

### Command Line Examples

```bash
# Run all tests
pytest -v

# Run with markers
pytest -v -m security

# Run with keyword filter
pytest -v -k "blocking"

# Run specific file
pytest -v tests/test_login_blocking.py

# Run with coverage
pytest --cov=backend --cov-report=html

# Run with HTML report
pytest --html=report.html --self-contained-html

# Run in parallel (requires pytest-xdist)
pytest -n auto

# Stop on first failure
pytest -x

# Show local variables on failure
pytest -l

# Show print statements
pytest -s
```

### Using the run_all_tests.sh Script

```bash
# Basic execution
./run_all_tests.sh

# With verbose output
./run_all_tests.sh -v

# With specific marker
./run_all_tests.sh -m security

# With keyword filter
./run_all_tests.sh -k "login"

# With coverage
./run_all_tests.sh --coverage

# With HTML report
./run_all_tests.sh --html

# Combine options
./run_all_tests.sh -v -m security --coverage --html
```

## Test Examples

### Login Blocking Test

```python
def test_level_1_block_on_3_failures(api_url, test_user):
    """Test that level 1 block is applied after 3 failed attempts"""
    username = test_user["username"]
    
    # Attempt 3 wrong passwords
    for i in range(3):
        response = requests.post(
            f"{api_url}/login",
            json={"username": username, "password": f"wrong_{i}"}
        )
        assert response.status_code == 401
    
    # 4th attempt should be blocked
    response = requests.post(
        f"{api_url}/login",
        json={"username": username, "password": test_user["password"]}
    )
    assert response.status_code == 423  # Locked
```

### User Lock Status Test

```python
def test_temporarily_locked_user_shows_countdown(api_url, root_token, test_user):
    """Test that temporarily locked user shows countdown info"""
    username = test_user["username"]
    
    # Create 3 failed attempts
    for i in range(3):
        requests.post(
            f"{api_url}/login",
            json={"username": username, "password": f"wrong_{i}"}
        )
    
    # Check user status in list
    response = requests.get(
        f"{api_url}/users",
        headers={"Authorization": f"Bearer {root_token}"}
    )
    
    user_data = next(
        (u for u in response.json()["data"] if u["username"] == username),
        None
    )
    assert user_data["is_locked"] is True
    assert user_data["lock_type"] == "temporary"
    assert user_data["seconds_until_unlock"] is not None
```

## Continuous Integration

### GitHub Actions

Tests should be run automatically on:
- Push to main branch
- Pull requests
- Scheduled daily runs

Example workflow in `.github/workflows/tests.yml`:

```yaml
name: Run Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_USER: test_user
          POSTGRES_PASSWORD: test_password
          POSTGRES_DB: contracts_test
    
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install -r tests/requirements.txt
      - run: ./tests/run_all_tests.sh --coverage
```

## Troubleshooting

### Tests Fail to Connect to API

1. Ensure backend is running: `http://localhost:3000/api/health`
2. Check `API_URL` environment variable
3. Verify database is accessible
4. Check firewall/network settings

### Database Connection Issues

1. Verify PostgreSQL is running
2. Check credentials in `conftest.py`
3. Ensure test database exists
4. Check `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD` environment variables

### Import Errors

```bash
# Reinstall dependencies
pip install --force-reinstall -r requirements.txt

# Check Python version (should be 3.8+)
python --version
```

### Timeout Issues

- Increase timeout in fixture: `timeout=30` (in seconds)
- Check if backend is slow
- Verify network connectivity

## Adding New Tests

1. Create a new file: `test_<feature>.py`
2. Import required modules and fixtures
3. Add pytest markers
4. Write test functions with clear names
5. Use existing fixtures or create new ones in `conftest.py`
6. Run: `pytest -v tests/test_<feature>.py`
7. Commit to git with clear commit message

### Test Template

```python
"""
Feature: Description

Tests for:
- Functionality 1
- Functionality 2
"""

import pytest
import requests


@pytest.mark.feature_name
class TestFeature:
    """Tests for feature"""
    
    def test_something(self, api_url, root_token):
        """Test description"""
        response = requests.get(
            f"{api_url}/endpoint",
            headers={"Authorization": f"Bearer {root_token}"}
        )
        assert response.status_code == 200
```

## Coverage Goals

- **Overall**: > 80%
- **Security**: > 90%
- **Core APIs**: > 85%
- **User Management**: > 90%
- **Blocking System**: > 95%

## Test Execution Time

- Unit tests: ~30s
- Integration tests: ~2m
- Security tests: ~5m
- All tests: ~10m (with parallelization)

## Best Practices

1. **Clear naming**: Test names should describe what is being tested
2. **Single responsibility**: Each test should verify one thing
3. **Use fixtures**: Share setup code via pytest fixtures
4. **Mock external services**: Don't make real API calls to external services
5. **Clean up**: Delete test data after tests complete
6. **Deterministic**: Tests should produce consistent results
7. **Fast**: Tests should run quickly (< 1s each)
8. **Isolated**: Tests should not depend on other tests running first

## Debugging Tests

```bash
# Show print statements
pytest -s tests/test_login_blocking.py

# Show local variables on failure
pytest -l tests/test_login_blocking.py::test_level_1_block_on_3_failures

# Stop on first failure
pytest -x tests/test_login_blocking.py

# Run with pdb (Python debugger) on failure
pytest --pdb tests/test_login_blocking.py

# Drop into pdb on assertion
pytest --pdbcls=IPython.terminal.debugger:TerminalPdb tests/test_login_blocking.py
```

## License

These tests are part of the CHOP project and are licensed under AGPL-3.0.