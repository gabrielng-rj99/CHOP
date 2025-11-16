-- Migration: Add status column to categories table
-- Date: 2024

-- Add status column if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'categories'
        AND column_name = 'status'
    ) THEN
        ALTER TABLE categories ADD COLUMN status VARCHAR(50) NOT NULL DEFAULT 'ativo';
    END IF;
END $$;

-- Update existing categories based on their usage in active contracts
UPDATE categories
SET status = CASE
    WHEN EXISTS (
        SELECT 1
        FROM contracts c
        INNER JOIN lines l ON c.line_id = l.id
        WHERE l.category_id = categories.id
        AND c.archived_at IS NULL
        AND (c.end_date IS NULL OR c.end_date > NOW())
    ) THEN 'ativo'
    ELSE 'inativo'
END
WHERE archived_at IS NULL;

-- Archived categories remain with their current status or default
UPDATE categories
SET status = 'inativo'
WHERE archived_at IS NOT NULL AND status IS NULL;
