-- Add role support for teacher onboarding and authentication
ALTER TABLE "teachers"
ADD COLUMN "role" "AdminRole" NOT NULL DEFAULT 'STAFF';
