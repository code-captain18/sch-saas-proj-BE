/*
  Warnings:

  - Added the required column `passwordHash` to the `admin_users` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "admin_users" ADD COLUMN     "passwordHash" TEXT NOT NULL;
