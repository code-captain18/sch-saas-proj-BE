import express from "express";
import jwt from "jsonwebtoken";
import prisma from "./prisma.js";
import { canSchoolAccess, isSubscriptionEnforcementEnabled } from "./subscription.js";
import type { Permission, RequestWithUser, Role } from "../types/app-types.js";

const jwtSecret = process.env.JWT_SECRET ?? process.env.AUTH_JWT_SECRET ?? "dev-only-change-me";

const rolePermissions: Record<string, string[]> = {
    SUPER_ADMIN: ["*"],
    PRINCIPAL: [
        "students:read",
        "teachers:read",
        "classes:read",
        "subjects:read",
        "fees:read",
        "reports:read",
        "audit:read",
    ],
    SCHOOL_ADMIN: [
        "schools:read",
        "schools:write",
        "settings:write",
        "students:read",
        "students:write",
        "teachers:read",
        "teachers:write",
        "classes:read",
        "classes:write",
        "subjects:read",
        "subjects:write",
        "fees:read",
        "fees:write",
        "reports:read",
        "audit:read",
    ],
    ACCOUNTANT: [
        "settings:write",
        "students:read",
        "teachers:read",
        "classes:read",
        "subjects:read",
        "fees:read",
        "fees:write",
        "reports:read",
        "audit:read",
    ],
    STAFF: ["students:read", "teachers:read", "classes:read", "subjects:read", "reports:read"],
    VIEWER: ["students:read", "teachers:read", "classes:read", "subjects:read", "fees:read", "reports:read", "audit:read"],
};

function isRole(value: string): value is Role {
    return ["SUPER_ADMIN", "PRINCIPAL", "SCHOOL_ADMIN", "ACCOUNTANT", "STAFF", "VIEWER"].includes(value);
}

function resolveRequestedSchoolId(req: express.Request): string | null {
    return (
        (typeof req.query.schoolId === "string" ? req.query.schoolId : null) ||
        (typeof req.body?.schoolId === "string" ? req.body.schoolId : null)
    );
}

function hasPermission(role: Role, permission: Permission) {
    const permissions = rolePermissions[role];
    return permissions.includes("*") || permissions.includes(permission);
}

export async function authenticate(req: RequestWithUser, res: express.Response, next: express.NextFunction) {
    const authHeader = req.header("authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        res.status(401).json({ error: "Unauthorized: missing bearer token" });
        return;
    }

    const token = authHeader.slice(7).trim();

    try {
        const payload = jwt.verify(token, jwtSecret) as jwt.JwtPayload & {
            sub?: string;
            role?: string;
            schoolId?: string | null;
            userType?: string;
        };

        if (!payload.sub || !payload.role || !isRole(payload.role)) {
            res.status(401).json({ error: "Unauthorized: invalid token payload" });
            return;
        }

        req.authUser = {
            userId: payload.sub,
            role: payload.role,
            schoolId: payload.schoolId ?? null,
            userType: payload.userType === "TEACHER" ? "TEACHER" : "ADMIN_USER",
        };

        if (isSubscriptionEnforcementEnabled() && payload.role !== "SUPER_ADMIN" && payload.schoolId) {
            const school = await prisma.school.findUnique({
                where: { id: payload.schoolId },
                select: {
                    isActive: true,
                    createdAt: true,
                    subscriptionStartedAt: true,
                    subscriptionTrialEndsAt: true,
                    subscriptionPaidUntil: true,
                },
            });

            if (!school) {
                res.status(403).json({ error: "Forbidden: school not found" });
                return;
            }

            const access = canSchoolAccess(school);
            if (!access.allowed) {
                res.status(403).json({ error: access.reason });
                return;
            }
        }

        next();
    } catch {
        res.status(401).json({ error: "Unauthorized: invalid or expired token" });
    }
}

export function authorize(req: RequestWithUser, res: express.Response, permission: Permission) {
    const authUser = req.authUser;
    if (!authUser) {
        res.status(401).json({ error: "Unauthorized" });
        return null;
    }

    const role = authUser.role;
    if (!hasPermission(role, permission)) {
        res.status(403).json({ error: "Forbidden: insufficient role permissions" });
        return null;
    }

    const requestedSchoolId = resolveRequestedSchoolId(req);
    const schoolId = role === "SUPER_ADMIN" ? requestedSchoolId : authUser.schoolId;

    if (role !== "SUPER_ADMIN" && !schoolId) {
        res.status(403).json({ error: "Forbidden: missing school scope for this user" });
        return null;
    }

    return { role, schoolId, userId: authUser.userId };
}
