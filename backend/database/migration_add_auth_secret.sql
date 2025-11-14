-- Migration: Add auth_secret to existing users
-- This script updates users table to add auth_secret for existing users

-- Step 0: Enable pgcrypto extension for SHA256 function
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Step 1: Add updated_at column if not exists (should already exist from init.sql)
ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP;

-- Step 2: Add auth_secret column if not exists (should already exist from init.sql)
ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_secret VARCHAR(64);

-- Step 3: Update updated_at for existing users if NULL
UPDATE users
SET updated_at = COALESCE(updated_at, created_at, CURRENT_TIMESTAMP)
WHERE updated_at IS NULL;

-- Step 4: Generate and update auth_secret for existing users
-- Generate auth_secret as SHA256(id + updated_at) for each user
UPDATE users
SET auth_secret = encode(digest(id::text || updated_at::text, 'sha256'), 'hex')
WHERE auth_secret IS NULL OR auth_secret = '';

-- Step 5: Make auth_secret NOT NULL after populating
ALTER TABLE users ALTER COLUMN auth_secret SET NOT NULL;

-- Verification query (optional - shows status of all users)
SELECT
    id,
    username,
    created_at,
    updated_at,
    CASE
        WHEN auth_secret IS NOT NULL AND length(auth_secret) = 64 THEN '✓ OK'
        ELSE '✗ MISSING'
    END as auth_secret_status
FROM users
ORDER BY created_at DESC;

-- Success message
DO $$
BEGIN
    RAISE NOTICE 'Migration completed successfully:';
    RAISE NOTICE '- pgcrypto extension enabled';
    RAISE NOTICE '- updated_at column verified/added';
    RAISE NOTICE '- auth_secret column verified/added';
    RAISE NOTICE '- auth_secret generated and populated for all users';
END $$;
