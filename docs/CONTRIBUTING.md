# Contributing to Entity Hub

Thank you for your interest in contributing to Entity Hub! This guide will help you get started.

## Getting Started

### 1. Fork and Clone

```bash
git clone https://github.com/your-username/Entity-Hub-Open-Project.git
cd Entity-Hub-Open-Project
```

### 2. Create a Branch

```bash
git checkout -b feature/description
# or
git checkout -b fix/description
```

**Branch naming convention:**
- `feature/` — New functionality
- `fix/` — Bug fixes
- `docs/` — Documentation updates
- `refactor/` — Code refactoring
- `test/` — Test additions/fixes
- `chore/` — Maintenance tasks

### 3. Setup Development Environment

**Backend:**
```bash
cd backend
go mod tidy
go test ./... -v
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

**Tests:**
```bash
cd tests
pip install -r requirements.txt
docker compose -f docker-compose.test.yml up -d
python run_tests.py
```

## Code Standards

### Go Backend

```go
// ✓ Good - clear validation and error handling
func (s *UserStore) CreateUser(username, displayName, password, role string) (string, error) {
    if err := ValidateUsername(username); err != nil {
        return "", err
    }
    
    if err := ValidateStrongPassword(password); err != nil {
        return "", err
    }
    
    // ... implementation
    return id, nil
}

// ✗ Bad - no validation, unclear errors
func CreateUser(u string, p string) string {
    // direct insert without checks
    return id
}
```

### Error Messages

```go
// ✓ Descriptive
return fmt.Errorf("user not found: %s", username)
return errors.New("password must be at least 16 characters")

// ✗ Generic
return errors.New("error")
return errors.New("invalid")
```

### Naming Conventions

| Type | Convention | Example |
|------|------------|---------|
| Structs | PascalCase | `UserStore`, `Contract` |
| Methods | PascalCase | `CreateUser`, `GetByID` |
| Variables | camelCase | `clientID`, `startDate` |
| Constants | UPPER_SNAKE | `MAX_PASSWORD_LENGTH` |
| Files | snake_case | `user_store.go` |

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description

[optional body]

[optional footer]
```

**Types:**
- `feat` — New feature
- `fix` — Bug fix
- `docs` — Documentation
- `refactor` — Code refactoring
- `test` — Adding/fixing tests
- `chore` — Maintenance
- `security` — Security improvements

**Examples:**
```bash
git commit -m "feat(auth): add password strength validation"
git commit -m "fix(api): return 403 for unauthorized user access"
git commit -m "docs: update API endpoint documentation"
git commit -m "test(security): add SQL injection test cases"
```

## Testing Requirements

### Before Submitting

1. **Run existing tests:**
   ```bash
   # Go unit tests
   cd backend && go test ./... -v
   
   # Python security tests
   cd tests && python run_tests.py
   ```

2. **Add tests for new code:**
   - Unit tests for new functions
   - Integration tests for new endpoints
   - Security tests if touching auth/validation

### Test Structure

```go
func TestCreateUser_ValidatesPassword(t *testing.T) {
    // Arrange
    store := setupTestStore(t)
    
    // Act
    _, err := store.CreateUser("testuser", "Test User", "weak", "user")
    
    // Assert
    require.Error(t, err)
    require.Contains(t, err.Error(), "at least 16 characters")
}
```

## Pull Request Process

### 1. Before Creating PR

- [ ] Code follows project conventions
- [ ] Tests pass locally
- [ ] New tests added for new functionality
- [ ] Documentation updated if needed
- [ ] No console.log or debug prints
- [ ] `go fmt ./...` run on Go code

### 2. PR Template

```markdown
## Description
Brief description of changes and why.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Tests added/updated
- [ ] All tests pass

## Security Checklist (if applicable)
- [ ] Input validation added
- [ ] SQL uses prepared statements
- [ ] Sensitive data not logged
- [ ] Authorization checks in place

## Related Issues
Closes #123
```

### 3. Review Process

- At least one approval required
- All CI checks must pass
- Address review feedback promptly

## Security Guidelines

### Required Practices

1. **Never expose sensitive data:**
   ```go
   type User struct {
       PasswordHash string `json:"-"`      // Hidden from JSON
       AuthSecret   string `json:"-"`      // Hidden from JSON
   }
   ```

2. **Use prepared statements:**
   ```go
   // ✓ Correct
   db.QueryRow("SELECT * FROM users WHERE id = $1", userID)
   
   // ✗ Never do this
   db.QueryRow("SELECT * FROM users WHERE id = '" + userID + "'")
   ```

3. **Validate all inputs:**
   ```go
   if err := ValidateUsername(username); err != nil {
       return "", err
   }
   ```

4. **Check authorization:**
   ```go
   if claims.Role != "admin" && claims.Role != "root" {
       return http.StatusForbidden, "Access denied"
   }
   ```

## Reporting Bugs

Open an issue with:

1. **Clear description** of the problem
2. **Steps to reproduce**
3. **Expected vs actual behavior**
4. **Environment** (Go version, OS, browser)
5. **Logs/screenshots** if applicable

## Feature Requests

Open a discussion or issue with:

1. Problem being solved
2. Proposed solution
3. Alternatives considered
4. Impact on existing functionality

## Development Tips

### Adding a New Entity

1. Define model in `backend/domain/models.go`
2. Create store in `backend/store/entity_store.go`
3. Write tests in `backend/store/entity_store_test.go`
4. Add handlers in `backend/server/entity_handlers.go`
5. Register routes in `backend/server/routes.go`
6. Update database schema if needed
7. Add security tests in `tests/test_api_endpoints.py`

### Debugging

```go
// Use structured logging
log.Printf("Creating user: username=%s, role=%s", username, role)

// Check response codes in tests
assert response.status_code == 200, f"Unexpected: {response.text}"
```

## Getting Help

- 📖 Read [ARCHITECTURE.md](ARCHITECTURE.md)
- 💬 Open a GitHub Discussion
- 🐛 File an Issue

---

Thank you for contributing to Entity Hub! 🙌