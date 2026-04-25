-- DropForeignKey
ALTER TABLE "classes" DROP CONSTRAINT "classes_assistantTeacherId_fkey";

-- DropIndex
DROP INDEX "classes_assistantTeacherId_idx";

-- DropIndex
DROP INDEX "idx_students_guardian_info";

-- AlterTable
ALTER TABLE "schools" ADD COLUMN     "logo" TEXT;

-- AddForeignKey
ALTER TABLE "classes" ADD CONSTRAINT "classes_assistantTeacherId_fkey" FOREIGN KEY ("assistantTeacherId") REFERENCES "teachers"("id") ON DELETE SET NULL ON UPDATE CASCADE;
