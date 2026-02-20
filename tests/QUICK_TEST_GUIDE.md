# EHOP Login Blocking System - Quick Test Guide

## Overview

This guide demonstrates how to quickly test the login blocking system that was just implemented and fixed.

## Prerequisites

- Backend running: `http://localhost:3000`
- Frontend running: `http://localhost:5173`
- Test user credentials (or create your own)

## Quick Start - Using Makefile (Recommended)

### Run Login Blocking Tests Only

```bash
make test-blocking
```

This runs all tests related to the login blocking system:
- Progressive lock levels (1, 2, 3, 4)
- Manual admin blocking
- User lock status display
- JWT validation during blocks
- Block expiration

### Run All Tests

```bash
make test
```

### Run Tests with Coverage

```bash
make test-coverage
```

### Run Tests with HTML Report

```bash
make test-coverage --html
```

## Alternative - Using run_all_tests.sh Directly

```bash
# All tests
./tests/run_all_tests.sh

# With verbose output
./tests/run_all_tests.sh -v

# Only login blocking tests
./tests/run_all_tests.sh -m login_blocking

# Tests matching keyword "blocking"
./tests/run_all_tests.sh -k "blocking"

# With coverage report
./tests/run_all_tests.sh --coverage

# With HTML report
./tests/run_all_tests.sh --html
```

## Manual Testing via Frontend

### Test Level 1 Block (3 failed attempts → 5 min lock)

1. Open frontend: `http://localhost:5173`
2. Go to Users page (admin only)
3. In browser console or via login endpoint, attempt 3 wrong passwords:
   ```bash
   for i in {1..3}; do
     curl -X POST http://localhost:3000/api/login \
       -H "Content-Type: application/json" \
       -d '{"username":"teste","password":"wrong_'$i'"}'
     sleep 1
   done
   ```
4. On frontend Users page:
   - User should show: 🔒 **Bloqueado Temp. (Nível 1)**
   - Countdown timer showing ~5 minutes
5. Attempt correct password → Should get 423 (Locked) response
6. Wait 5+ minutes → Should be able to login again

### Test Level 4 Block (15 failed attempts → permanent)

1. In terminal, attempt 15 wrong passwords:
   ```bash
   for i in {1..15}; do
     curl -X POST http://localhost:3000/api/login \
       -H "Content-Type: application/json" \
       -d '{"username":"teste","password":"wrong_'$i'"}'
     sleep 0.2
   done
   ```
2. On frontend Users page:
   - User should show: 🔒 **Bloqueado Permanente (Nível 4)**
   - **NO countdown** (permanent until admin unblocks)
3. Attempt correct password → Should get 423 (Locked)

### Test Manual Admin Block

1. As root/admin, navigate to Users page
2. Click lock icon on a user
3. User should immediately show:
   - 🔒 **Bloqueado Permanente (Nível 3)**
   - Cannot login with correct password
4. Click unlock icon to unblock
5. User can login again

## Test via curl/API

### Check User Lock Status

```bash
# Get root token first
TOKEN=$(curl -s -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"root","password":"THIS_IS_A_DEV_ENVIRONMENT_PASSWORD!123abc"}' \
  | jq -r '.data.token')

# Get users list with lock status
curl -s -X GET http://localhost:3000/api/users \
  -H "Authorization: Bearer $TOKEN" | jq '.data[] | {
    username,
    is_locked,
    lock_type,
    lock_level,
    seconds_until_unlock
  }'
```

### Block a User Manually

```bash
curl -X PUT http://localhost:3000/api/users/teste/block \
  -H "Authorization: Bearer $TOKEN"
```

### Unblock a User

```bash
curl -X PUT http://localhost:3000/api/users/teste/unlock \
  -H "Authorization: Bearer $TOKEN"
```

### Try Login (Should be Blocked)

```bash
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"teste","password":"correct_password"}' \
  | jq '.message'
```

Expected response:
```json
{
  "message": "Conta bloqueada...",
  "error": "Locked"
}
HTTP Status: 423
```

## Watch Backend Logs During Testing

```bash
# Watch all backend logs
make logs-backend

# Watch only blocking system logs (filtered)
make logs-blocking

# In another terminal, run tests
make test-blocking
```

You should see logs like:
```
🔍 DEBUG Login Check: user=teste, lockedUntil.Valid=true, lock_level=1, failed_attempts=3
🔍 DEBUG Time Check: locked_until=..., now=..., isBefore=true
🚫 Login bloqueado: user=teste, lock_level=1, locked_until=...
```

## Test Scenarios Checklist

### Progressive Blocking
- [ ] 1-2 failed attempts: Can still login with correct password
- [ ] 3 failed attempts: Blocked for 5 minutes (Level 1)
- [ ] 5 failed attempts: Blocked for 15 minutes (Level 2)
- [ ] 10 failed attempts: Blocked for 1 hour (Level 3)
- [ ] 15 failed attempts: Permanently blocked (Level 4)

### Lock Status Display
- [ ] Unlocked user shows: **Ativo** (green)
- [ ] Temp locked shows: 🔒 **Bloqueado Temp. (Nível X)** with countdown
- [ ] Permanent locked shows: 🔒 **Bloqueado Permanente (Nível X)** without countdown

### Manual Blocking
- [ ] Admin can block user manually
- [ ] Blocked user cannot login (correct password still fails)
- [ ] Admin can unblock user
- [ ] Unblocked user can login again

### JWT Validation
- [ ] User with valid JWT cannot use it after being blocked
- [ ] Existing refresh token becomes invalid after block
- [ ] Logout and re-login after unlock works

### Block Expiration
- [ ] Level 1 block expires after ~5 minutes
- [ ] Level 2 block expires after ~15 minutes
- [ ] Level 3 block expires after ~1 hour
- [ ] Level 4 block never expires (manual unlock required)

## Troubleshooting

### Backend won't start
```bash
make clean-backend
make build
```

### Tests fail to connect
- Verify backend is running: `curl http://localhost:3000/health`
- Check `API_URL` in tests/conftest.py
- Ensure test database exists

### Pytest import errors
```bash
pip install -r tests/requirements.txt --force-reinstall
```

### Tests timeout
- Backend might be slow
- Check: `curl -v http://localhost:3000/health`
- Increase timeout in fixture if needed

## Key Files for Reference

- **Backend Implementation**: `backend/store/user_store.go` (AuthenticateUser function)
- **API Response**: `backend/server/users_handlers.go` (UserResponse struct)
- **Frontend Display**: `frontend/src/components/users/UsersTable.jsx` (LockStatusBadge component)
- **Tests**: `tests/test_login_blocking.py`
- **Documentation**: `tests/README.md`

## Expected Test Results

When running `make test-blocking`, you should see:

```
===== test session starts =====
collected 24 items

tests/test_login_blocking.py::TestProgressiveLocking::test_level_1_block_on_3_failures PASSED
tests/test_login_blocking.py::TestProgressiveLocking::test_level_2_block_on_5_failures PASSED
tests/test_login_blocking.py::TestProgressiveLocking::test_level_3_block_on_10_failures PASSED
tests/test_login_blocking.py::TestProgressiveLocking::test_level_4_permanent_block_on_15_failures PASSED
tests/test_login_blocking.py::TestUserLockStatus::test_unlocked_user_shows_no_lock PASSED
tests/test_login_blocking.py::TestUserLockStatus::test_temporarily_locked_user_shows_countdown PASSED
tests/test_login_blocking.py::TestManualBlocking::test_admin_can_block_user PASSED
tests/test_login_blocking.py::TestManualBlocking::test_manually_blocked_user_shows_permanent_lock PASSED
tests/test_login_blocking.py::TestManualBlocking::test_admin_can_unblock_user PASSED
tests/test_login_blocking.py::TestManualBlocking::test_user_cannot_block_themselves PASSED
tests/test_login_blocking.py::TestJWTValidationDuringBlock::test_existing_jwt_invalidated_when_user_blocked PASSED
tests/test_login_blocking.py::TestJWTValidationDuringBlock::test_refresh_token_denied_when_user_blocked PASSED
tests/test_login_blocking.py::TestBlockExpiration::test_temporary_block_expires_after_duration PASSED
tests/test_login_blocking.py::TestErrorMessages::test_blocked_user_gets_appropriate_message PASSED

===== 14 passed in 2.34s =====
✅ All tests passed!
```

## Next Steps

1. **Run tests**: `make test-blocking`
2. **Check frontend**: Visit `http://localhost:5173/users`
3. **Verify logs**: `make logs-blocking`
4. **Review code**: Check `tests/test_login_blocking.py` for detailed test logic
5. **Explore**: Use `make help` to see all available commands

## Contact & Documentation

- **Quick Reference**: This file (QUICK_TEST_GUIDE.md)
- **Complete Docs**: `tests/README.md`
- **Cleanup Summary**: `CLEANUP_SUMMARY.md`
- **Main README**: `README.md`

---

**Status**: ✅ Login blocking system fully implemented, tested, and documented!