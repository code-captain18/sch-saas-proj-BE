import type express from "express";
import type { Prisma } from "@prisma/client";

export type Role = "SUPER_ADMIN" | "PRINCIPAL" | "SCHOOL_ADMIN" | "ACCOUNTANT" | "STAFF" | "VIEWER";

export type Permission =
    | "schools:read"
    | "schools:write"
    | "settings:write"
    | "students:read"
    | "students:write"
    | "teachers:read"
    | "teachers:write"
    | "classes:read"
    | "classes:write"
    | "subjects:read"
    | "subjects:write"
    | "fees:read"
    | "fees:write"
    | "reports:read"
    | "audit:read";

export type AuthUser = {
    userId: string;
    role: Role;
    schoolId: string | null;
    userType: "ADMIN_USER" | "TEACHER";
};

export type RequestWithUser = express.Request & { authUser?: AuthUser };

export type FeeLineItem = { label: string; amount: number };

export type AdminContext = { role: Role; schoolId: string | null; userId: string };

export type AuditParams = {
    req?: express.Request;
    action: string;
    entityType: string;
    entityId?: string;
    schoolId?: string | null;
    actorUserId?: string | null;
    actorRole?: Role | null;
    status?: "SUCCESS" | "FAILED";
    metadata?: Prisma.InputJsonValue;
};
