-- CreateEnum
CREATE TYPE "StudentGender" AS ENUM ('MALE', 'FEMALE');

-- AlterTable
ALTER TABLE "students" ADD COLUMN "gender" "StudentGender";
