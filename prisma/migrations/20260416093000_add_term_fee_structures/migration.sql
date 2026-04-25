-- CreateEnum
CREATE TYPE "AcademicTerm" AS ENUM ('TERM_1', 'TERM_2', 'TERM_3');

-- CreateEnum
CREATE TYPE "FeeScopeType" AS ENUM ('CLASS', 'GRADE');

-- CreateTable
CREATE TABLE "fee_structures" (
    "id" TEXT NOT NULL,
    "schoolId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "academicYear" TEXT NOT NULL,
    "term" "AcademicTerm" NOT NULL,
    "scopeType" "FeeScopeType" NOT NULL,
    "classId" TEXT,
    "grade" TEXT,
    "items" JSONB NOT NULL,
    "totalAmount" DECIMAL(10, 2) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "fee_structures_pkey" PRIMARY KEY ("id")
);

-- AlterTable
ALTER TABLE "fee_invoices"
ADD COLUMN "academicYear" TEXT,
ADD COLUMN "feeStructureId" TEXT,
ADD COLUMN "lineItems" JSONB,
ADD COLUMN "term" "AcademicTerm" NOT NULL DEFAULT 'TERM_1';

-- CreateIndex
CREATE INDEX "fee_structures_schoolId_idx" ON "fee_structures"("schoolId");

-- CreateIndex
CREATE INDEX "fee_structures_classId_idx" ON "fee_structures"("classId");

-- CreateIndex
CREATE INDEX "fee_structures_grade_idx" ON "fee_structures"("grade");

-- CreateIndex
CREATE INDEX "fee_structures_term_idx" ON "fee_structures"("term");

-- CreateIndex
CREATE INDEX "fee_invoices_term_idx" ON "fee_invoices"("term");

-- CreateIndex
CREATE INDEX "fee_invoices_feeStructureId_idx" ON "fee_invoices"("feeStructureId");

-- CreateIndex
CREATE UNIQUE INDEX "fee_invoices_studentId_feeStructureId_key" ON "fee_invoices"("studentId", "feeStructureId");

-- AddForeignKey
ALTER TABLE "fee_structures" ADD CONSTRAINT "fee_structures_schoolId_fkey" FOREIGN KEY ("schoolId") REFERENCES "schools"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "fee_structures" ADD CONSTRAINT "fee_structures_classId_fkey" FOREIGN KEY ("classId") REFERENCES "classes"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "fee_invoices" ADD CONSTRAINT "fee_invoices_feeStructureId_fkey" FOREIGN KEY ("feeStructureId") REFERENCES "fee_structures"("id") ON DELETE SET NULL ON UPDATE CASCADE;