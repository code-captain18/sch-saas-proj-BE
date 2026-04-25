-- Add new columns to students table for comprehensive student registration

ALTER TABLE "students" 
ADD COLUMN "otherNames" TEXT,
ADD COLUMN "previousSchool" TEXT,
ADD COLUMN "picture" TEXT,
ADD COLUMN "medicalCondition" TEXT,
ADD COLUMN "allergies" TEXT,
ADD COLUMN "guardianInfo" JSONB;

-- Create index on guardianInfo for potential queries
CREATE INDEX idx_students_guardian_info ON "students" USING gin("guardianInfo");

-- Add comment for clarity on data structure
COMMENT ON COLUMN "students"."guardianInfo" IS 
'JSON structure: { 
  "father": { 
    "firstName": string, 
    "lastName": string, 
    "phone": string, 
    "email": string, 
    "occupation": string, 
    "residentialAddress": string, 
    "postalAddress": string 
  }, 
  "mother": { 
    "firstName": string, 
    "lastName": string, 
    "phone": string, 
    "email": string, 
    "occupation": string, 
    "residentialAddress": string, 
    "postalAddress": string 
  } 
}';
