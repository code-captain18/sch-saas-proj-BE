-- AlterTable: add phone to admin_users
ALTER TABLE "admin_users" ADD COLUMN "phone" TEXT;

-- CreateEnum
CREATE TYPE "OtpPurpose" AS ENUM ('LOGIN_MFA', 'FORGOT_PASSWORD', 'CHANGE_PASSWORD');

-- CreateTable
CREATE TABLE "otp_tokens" (
    "id" TEXT NOT NULL,
    "phone" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "purpose" "OtpPurpose" NOT NULL,
    "userId" TEXT,
    "userType" TEXT,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "usedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "otp_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "otp_tokens_phone_idx" ON "otp_tokens"("phone");

-- CreateIndex
CREATE INDEX "otp_tokens_purpose_userId_idx" ON "otp_tokens"("purpose", "userId");

-- CreateIndex
CREATE INDEX "otp_tokens_expiresAt_idx" ON "otp_tokens"("expiresAt");
