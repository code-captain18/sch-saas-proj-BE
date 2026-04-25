-- Add class leadership references (prefect and assistant prefect)
ALTER TABLE "classes"
ADD COLUMN "prefectStudentId" TEXT,
ADD COLUMN "assistantPrefectStudentId" TEXT;

ALTER TABLE "classes"
ADD CONSTRAINT "classes_prefectStudentId_fkey"
FOREIGN KEY ("prefectStudentId") REFERENCES "students"("id")
ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "classes"
ADD CONSTRAINT "classes_assistantPrefectStudentId_fkey"
FOREIGN KEY ("assistantPrefectStudentId") REFERENCES "students"("id")
ON DELETE SET NULL ON UPDATE CASCADE;

CREATE INDEX "classes_prefectStudentId_idx" ON "classes"("prefectStudentId");
CREATE INDEX "classes_assistantPrefectStudentId_idx" ON "classes"("assistantPrefectStudentId");
