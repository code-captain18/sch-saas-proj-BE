-- Alter teacher model with onboarding profile fields
ALTER TABLE "teachers"
ADD COLUMN "otherNames" TEXT,
ADD COLUMN "dateOfBirth" TIMESTAMP(3),
ADD COLUMN "ssnitNumber" TEXT,
ADD COLUMN "educationalLevel" TEXT,
ADD COLUMN "certifications" TEXT,
ADD COLUMN "picture" TEXT,
ADD COLUMN "maritalStatus" TEXT,
ADD COLUMN "nextOfKin" TEXT,
ADD COLUMN "nextOfKinRelationship" TEXT,
ADD COLUMN "residentialAddress" TEXT;
