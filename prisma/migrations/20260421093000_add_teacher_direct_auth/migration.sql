-- Add teacher password hash for direct authentication
ALTER TABLE "teachers"
ADD COLUMN "passwordHash" TEXT;

-- Add enum to distinguish session principal type
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'AuthSessionUserType') THEN
        CREATE TYPE "AuthSessionUserType" AS ENUM ('ADMIN_USER', 'TEACHER');
    END IF;
END $$;

-- Add userType to auth sessions with admin default for existing rows
ALTER TABLE "auth_sessions"
ADD COLUMN "userType" "AuthSessionUserType" NOT NULL DEFAULT 'ADMIN_USER';

-- Remove FK to admin_users so sessions can also represent teacher principals
ALTER TABLE "auth_sessions"
DROP CONSTRAINT IF EXISTS "auth_sessions_userId_fkey";

-- Replace old userId index with composite type+id index
DROP INDEX IF EXISTS "auth_sessions_userId_idx";
CREATE INDEX "auth_sessions_userType_userId_idx" ON "auth_sessions"("userType", "userId");
