-- Add assistant teacher field to Class model
ALTER TABLE "classes"
ADD COLUMN "assistantTeacherId" TEXT;

-- Add index for assistantTeacherId
CREATE INDEX "classes_assistantTeacherId_idx" ON "classes"("assistantTeacherId");

-- Add foreign key constraint for assistantTeacherId (optional, soft delete)
ALTER TABLE "classes"
ADD CONSTRAINT "classes_assistantTeacherId_fkey"
FOREIGN KEY ("assistantTeacherId")
REFERENCES "teachers"("id")
ON DELETE SET NULL;
