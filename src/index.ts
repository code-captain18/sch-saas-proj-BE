// Import Sentry instrumentation first
import "./instrument.js";
import * as Sentry from "@sentry/node";

const dbUrl = process.env.DATABASE_URL || "";
console.log("Environment check:", {
    PORT: process.env.PORT,
    DATABASE_URL: dbUrl ? `${dbUrl.substring(0, 20)}...${dbUrl.substring(dbUrl.length - 20)}` : "NOT SET",
    JWT_SECRET: process.env.JWT_SECRET ? "SET" : "NOT SET",
    SENTRY_DSN: process.env.SENTRY_DSN ? "SET" : "NOT SET"
});

import cors from "cors";
import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { Prisma } from "@prisma/client";
import prisma from "./lib/prisma.js";
import { validateBody, validateQuery } from "./lib/middleware.js";
import {
    loginSchema,
    refreshTokenSchema,
    createSchoolSchema,
    updateSchoolSchema,
    createStudentSchema,
    createTeacherSchema,
    createClassSchema,
    createSubjectSchema,
    createFeeInvoiceSchema,
    auditLogsQuerySchema,
} from "./lib/validations.js";

const app = express();
const port = Number(process.env.PORT ?? 4000);
const frontendOrigin = process.env.FRONTEND_ORIGIN ?? "http://localhost:3000";
const jwtSecret = process.env.JWT_SECRET ?? process.env.AUTH_JWT_SECRET ?? "dev-only-change-me";
const accessTokenTtl = "15m";
const refreshTokenTtlDays = 7;

const rolePermissions: Record<string, string[]> = {
    SUPER_ADMIN: ["*"],
    SCHOOL_ADMIN: [
        "schools:read",
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
    ACCOUNTANT: ["fees:read", "fees:write", "reports:read", "audit:read"],
    STAFF: ["students:read", "teachers:read", "classes:read", "subjects:read", "reports:read"],
    VIEWER: ["students:read", "teachers:read", "classes:read", "subjects:read", "fees:read", "reports:read", "audit:read"],
};

type Role = "SUPER_ADMIN" | "SCHOOL_ADMIN" | "ACCOUNTANT" | "STAFF" | "VIEWER";
type Permission =
    | "schools:read"
    | "schools:write"
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

type AuthUser = {
    userId: string;
    role: Role;
    schoolId: string | null;
};

type RequestWithUser = express.Request & { authUser?: AuthUser };

function hashToken(token: string) {
    return crypto.createHash("sha256").update(token).digest("hex");
}

function createAccessToken(user: { id: string; role: Role; schoolId: string | null }) {
    return jwt.sign(
        {
            sub: user.id,
            role: user.role,
            schoolId: user.schoolId,
        },
        jwtSecret,
        { expiresIn: accessTokenTtl },
    );
}

async function createRefreshSession(userId: string) {
    const refreshToken = crypto.randomBytes(48).toString("hex");
    const tokenHash = hashToken(refreshToken);
    const expiresAt = new Date(Date.now() + refreshTokenTtlDays * 24 * 60 * 60 * 1000);

    await prisma.authSession.create({
        data: {
            userId,
            tokenHash,
            expiresAt,
        },
    });

    return refreshToken;
}

function isRole(value: string): value is Role {
    return ["SUPER_ADMIN", "SCHOOL_ADMIN", "ACCOUNTANT", "STAFF", "VIEWER"].includes(value);
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

function getClientIp(req: express.Request) {
    const forwardedFor = req.header("x-forwarded-for");
    if (forwardedFor) {
        return forwardedFor.split(",")[0]?.trim() ?? null;
    }

    return req.socket.remoteAddress ?? null;
}

function parseDateParam(value: unknown) {
    if (typeof value !== "string" || !value) return null;
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function csvEscape(value: unknown) {
    const stringValue = value === null || value === undefined ? "" : String(value);
    return `"${stringValue.replace(/"/g, '""')}"`;
}

function buildAuditCsv(logs: Array<{
    createdAt: Date;
    action: string;
    entityType: string;
    entityId: string | null;
    status: string;
    ipAddress: string | null;
    actorUser: { email: string; id: string; name: string; role: string } | null;
    actorUserId: string | null;
    actorRole: string | null;
    schoolId: string | null;
    metadata: Prisma.JsonValue;
}>) {
    const header = [
        "createdAt",
        "action",
        "entityType",
        "entityId",
        "status",
        "actorEmail",
        "actorUserId",
        "actorRole",
        "schoolId",
        "ipAddress",
        "metadata",
    ];

    const rows = logs.map((entry) => [
        entry.createdAt.toISOString(),
        entry.action,
        entry.entityType,
        entry.entityId,
        entry.status,
        entry.actorUser?.email ?? "",
        entry.actorUserId,
        entry.actorRole,
        entry.schoolId,
        entry.ipAddress,
        entry.metadata ? JSON.stringify(entry.metadata) : "",
    ]);

    return [header, ...rows].map((row) => row.map(csvEscape).join(",")).join("\n");
}

async function logAudit(params: {
    req?: express.Request;
    action: string;
    entityType: string;
    entityId?: string;
    schoolId?: string | null;
    actorUserId?: string | null;
    actorRole?: Role | null;
    status?: "SUCCESS" | "FAILED";
    metadata?: Prisma.InputJsonValue;
}) {
    try {
        await prisma.auditLog.create({
            data: {
                schoolId: params.schoolId ?? null,
                actorUserId: params.actorUserId ?? null,
                actorRole: params.actorRole ?? undefined,
                action: params.action,
                entityType: params.entityType,
                entityId: params.entityId,
                status: params.status ?? "SUCCESS",
                ipAddress: params.req ? getClientIp(params.req) : null,
                userAgent: params.req?.header("user-agent") ?? null,
                metadata: params.metadata,
            },
        });
    } catch (error) {
        console.error("Audit log write failed:", error);
    }
}

function authenticate(req: RequestWithUser, res: express.Response, next: express.NextFunction) {
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
        };

        if (!payload.sub || !payload.role || !isRole(payload.role)) {
            res.status(401).json({ error: "Unauthorized: invalid token payload" });
            return;
        }

        req.authUser = {
            userId: payload.sub,
            role: payload.role,
            schoolId: payload.schoolId ?? null,
        };

        next();
    } catch {
        res.status(401).json({ error: "Unauthorized: invalid or expired token" });
    }
}

function authorize(req: RequestWithUser, res: express.Response, permission: Permission) {
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

app.use(cors({ origin: frontendOrigin }));
app.use(express.json());

// Sentry request handler - must be after body parser
if (process.env.SENTRY_DSN) {
    Sentry.setupExpressErrorHandler(app);
}

app.post("/api/auth/login", validateBody(loginSchema), async (req, res) => {
    const { email, password } = req.body;

    const user = await prisma.adminUser.findUnique({ where: { email } });
    if (!user) {
        await logAudit({
            req,
            action: "AUTH_LOGIN",
            entityType: "AuthSession",
            status: "FAILED",
            metadata: { email, reason: "user_not_found" },
        });
        res.status(401).json({ error: "Invalid credentials" });
        return;
    }

    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
        await logAudit({
            req,
            action: "AUTH_LOGIN",
            entityType: "AuthSession",
            schoolId: user.schoolId,
            actorUserId: user.id,
            actorRole: user.role as Role,
            status: "FAILED",
            metadata: { email, reason: "invalid_password" },
        });
        res.status(401).json({ error: "Invalid credentials" });
        return;
    }

    const accessToken = createAccessToken({
        id: user.id,
        role: user.role as Role,
        schoolId: user.schoolId,
    });
    const refreshToken = await createRefreshSession(user.id);

    await logAudit({
        req,
        action: "AUTH_LOGIN",
        entityType: "AuthSession",
        schoolId: user.schoolId,
        actorUserId: user.id,
        actorRole: user.role as Role,
        status: "SUCCESS",
        metadata: { email },
    });

    res.json({
        accessToken,
        refreshToken,
        user: {
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role,
            schoolId: user.schoolId,
        },
    });
});

app.post("/api/auth/refresh", validateBody(refreshTokenSchema), async (req, res) => {
    const { refreshToken } = req.body;

    const tokenHash = hashToken(refreshToken);
    const session = await prisma.authSession.findUnique({
        where: { tokenHash },
        include: { user: true },
    });

    if (!session || session.revokedAt || session.expiresAt <= new Date()) {
        await logAudit({
            req,
            action: "AUTH_REFRESH",
            entityType: "AuthSession",
            status: "FAILED",
            metadata: { reason: "invalid_or_expired_refresh_token" },
        });
        res.status(401).json({ error: "Invalid refresh token" });
        return;
    }

    await prisma.authSession.update({
        where: { id: session.id },
        data: { revokedAt: new Date() },
    });

    const newRefreshToken = await createRefreshSession(session.userId);
    const accessToken = createAccessToken({
        id: session.user.id,
        role: session.user.role as Role,
        schoolId: session.user.schoolId,
    });

    await logAudit({
        req,
        action: "AUTH_REFRESH",
        entityType: "AuthSession",
        schoolId: session.user.schoolId,
        actorUserId: session.user.id,
        actorRole: session.user.role as Role,
        status: "SUCCESS",
    });

    res.json({
        accessToken,
        refreshToken: newRefreshToken,
    });
});

app.post("/api/auth/logout", authenticate, async (req, res) => {
    const authUser = (req as RequestWithUser).authUser;
    if (!authUser) {
        res.status(401).json({ error: "Unauthorized" });
        return;
    }

    const { refreshToken } = req.body ?? {};

    if (refreshToken && typeof refreshToken === "string") {
        const tokenHash = hashToken(refreshToken);
        await prisma.authSession.updateMany({
            where: {
                tokenHash,
                userId: authUser.userId,
                revokedAt: null,
            },
            data: { revokedAt: new Date() },
        });
    } else {
        await prisma.authSession.updateMany({
            where: {
                userId: authUser.userId,
                revokedAt: null,
            },
            data: { revokedAt: new Date() },
        });
    }

    await logAudit({
        req,
        action: "AUTH_LOGOUT",
        entityType: "AuthSession",
        schoolId: authUser.schoolId,
        actorUserId: authUser.userId,
        actorRole: authUser.role,
        status: "SUCCESS",
    });

    res.json({ ok: true });
});

app.get("/api/auth/me", authenticate, async (req, res) => {
    const authUser = (req as RequestWithUser).authUser;
    if (!authUser) {
        res.status(401).json({ error: "Unauthorized" });
        return;
    }

    const user = await prisma.adminUser.findUnique({ where: { id: authUser.userId } });
    if (!user) {
        res.status(404).json({ error: "User not found" });
        return;
    }

    res.json({
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        schoolId: user.schoolId,
    });
});

app.get("/api/health", (_req, res) => {
    res.json({ ok: true, service: "school-saas-backend", database: "connected" });
});

app.get("/api/dashboard/stats", async (_req, res) => {
    try {
        const [totalSchools, totalStudents, activeTeachers, attendanceRecords] = await Promise.all([
            prisma.school.count(),
            prisma.student.count({ where: { status: "ACTIVE" } }),
            prisma.teacher.count({ where: { status: "ACTIVE" } }),
            prisma.attendance.findMany({
                where: {
                    date: {
                        gte: new Date(new Date().setHours(0, 0, 0, 0)),
                        lt: new Date(new Date().setHours(23, 59, 59, 999)),
                    },
                },
            }),
        ]);

        const presentCount = attendanceRecords.filter((a) => a.status === "PRESENT").length;
        const attendanceRate = attendanceRecords.length > 0
            ? ((presentCount / attendanceRecords.length) * 100).toFixed(1)
            : "0.0";

        res.json({
            totalSchools,
            totalStudents,
            activeTeachers,
            attendanceRate: parseFloat(attendanceRate),
            feeCollectionRate: 88.7, // Placeholder until fee module is built
        });
    } catch (error) {
        console.error("Error fetching dashboard stats:", error);
        res.status(500).json({ error: "Failed to fetch dashboard stats" });
    }
});

app.get("/api/schools", async (_req, res) => {
    try {
        const schools = await prisma.school.findMany({
            where: { isActive: true },
            orderBy: { name: "asc" },
        });
        res.json(schools);
    } catch (error) {
        console.error("Error fetching schools:", error);
        res.status(500).json({ error: "Failed to fetch schools" });
    }
});

app.get("/api/schools/:id", async (req, res) => {
    try {
        const schoolId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
        if (!schoolId) {
            res.status(400).json({ error: "school id is required" });
            return;
        }

        const school = await prisma.school.findUnique({
            where: { id: schoolId },
            include: {
                students: true,
                teachers: true,
                classes: true,
                subjects: true,
            },
        });

        if (!school) {
            return res.status(404).json({ error: "School not found" });
        }

        res.json(school);
    } catch (error) {
        console.error("Error fetching school:", error);
        res.status(500).json({ error: "Failed to fetch school" });
    }
});

app.use("/api/admin", authenticate);

app.get("/api/admin/schools", async (req, res) => {
    const context = authorize(req, res, "schools:read");
    if (!context) return;

    const schools = await prisma.school.findMany({
        where: context.role === "SUPER_ADMIN" ? undefined : { id: context.schoolId ?? "" },
        orderBy: { name: "asc" },
    });

    res.json(schools);
});

app.post("/api/admin/schools", validateBody(createSchoolSchema), async (req, res) => {
    const context = authorize(req, res, "schools:write");
    if (!context) return;

    const school = await prisma.school.create({
        data: {
            name: req.body.name,
            district: req.body.district,
            address: req.body.address,
            phone: req.body.phone,
            email: req.body.email,
        },
    });

    await logAudit({
        req,
        action: "SCHOOL_CREATE",
        entityType: "School",
        entityId: school.id,
        schoolId: school.id,
        actorUserId: context.userId,
        actorRole: context.role,
        metadata: { name: school.name, district: school.district },
    });

    res.status(201).json(school);
});

app.patch("/api/admin/schools/:id", validateBody(updateSchoolSchema), async (req, res) => {
    const context = authorize(req, res, "schools:write");
    if (!context) return;

    const schoolIdParam = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    if (!schoolIdParam) {
        res.status(400).json({ error: "school id is required" });
        return;
    }

    const existing = await prisma.school.findUnique({ where: { id: schoolIdParam } });
    if (!existing) {
        res.status(404).json({ error: "School not found" });
        return;
    }

    const school = await prisma.school.update({
        where: { id: schoolIdParam },
        data: {
            name: req.body.name,
            district: req.body.district,
            address: req.body.address,
            phone: req.body.phone,
            email: req.body.email,
        },
    });

    await logAudit({
        req,
        action: "SCHOOL_UPDATE",
        entityType: "School",
        entityId: school.id,
        schoolId: school.id,
        actorUserId: context.userId,
        actorRole: context.role,
        metadata: {
            name: school.name,
            district: school.district,
            address: school.address,
            phone: school.phone,
            email: school.email,
        },
    });

    res.json(school);
});

app.patch("/api/admin/schools/:id/deactivate", async (req, res) => {
    const context = authorize(req, res, "schools:write");
    if (!context) return;

    const schoolIdParam = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    if (!schoolIdParam) {
        res.status(400).json({ error: "school id is required" });
        return;
    }

    const existing = await prisma.school.findUnique({ where: { id: schoolIdParam } });
    if (!existing) {
        res.status(404).json({ error: "School not found" });
        return;
    }

    const school = await prisma.school.update({
        where: { id: schoolIdParam },
        data: { isActive: false },
    });

    await logAudit({
        req,
        action: "SCHOOL_DEACTIVATE",
        entityType: "School",
        entityId: school.id,
        schoolId: school.id,
        actorUserId: context.userId,
        actorRole: context.role,
        metadata: { name: school.name, district: school.district },
    });

    res.json(school);
});

app.patch("/api/admin/schools/:id/activate", async (req, res) => {
    const context = authorize(req, res, "schools:write");
    if (!context) return;

    const schoolIdParam = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    if (!schoolIdParam) {
        res.status(400).json({ error: "school id is required" });
        return;
    }

    const existing = await prisma.school.findUnique({ where: { id: schoolIdParam } });
    if (!existing) {
        res.status(404).json({ error: "School not found" });
        return;
    }

    const school = await prisma.school.update({
        where: { id: schoolIdParam },
        data: { isActive: true },
    });

    await logAudit({
        req,
        action: "SCHOOL_ACTIVATE",
        entityType: "School",
        entityId: school.id,
        schoolId: school.id,
        actorUserId: context.userId,
        actorRole: context.role,
        metadata: { name: school.name, district: school.district },
    });

    res.json(school);
});

app.delete("/api/admin/schools/:id", async (req, res) => {
    const context = authorize(req, res, "schools:write");
    if (!context) return;

    const schoolIdParam = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    if (!schoolIdParam) {
        res.status(400).json({ error: "school id is required" });
        return;
    }

    const existing = await prisma.school.findUnique({ where: { id: schoolIdParam } });
    if (!existing) {
        res.status(404).json({ error: "School not found" });
        return;
    }

    await prisma.school.delete({ where: { id: schoolIdParam } });

    await logAudit({
        req,
        action: "SCHOOL_DELETE",
        entityType: "School",
        entityId: existing.id,
        schoolId: existing.id,
        actorUserId: context.userId,
        actorRole: context.role,
        metadata: { name: existing.name, district: existing.district },
    });

    res.json({ ok: true });
});

app.get("/api/admin/students", async (req, res) => {
    const context = authorize(req, res, "students:read");
    if (!context) return;

    const where = context.schoolId ? { schoolId: context.schoolId } : undefined;
    const students = await prisma.student.findMany({
        where,
        include: { class: true },
        orderBy: { createdAt: "desc" },
    });
    res.json(students);
});

app.post("/api/admin/students", validateBody(createStudentSchema), async (req, res) => {
    const context = authorize(req, res, "students:write");
    if (!context) return;

    const schoolId = context.schoolId ?? req.body.schoolId;
    if (!schoolId) {
        res.status(400).json({ error: "schoolId is required" });
        return;
    }

    const student = await prisma.student.create({
        data: {
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            email: req.body.email,
            dateOfBirth: new Date(req.body.dateOfBirth),
            schoolId,
            classId: req.body.classId,
        },
    });
    await logAudit({
        req,
        action: "STUDENT_CREATE",
        entityType: "Student",
        entityId: student.id,
        schoolId,
        actorUserId: context.userId,
        actorRole: context.role,
        metadata: { firstName: student.firstName, lastName: student.lastName },
    });
    res.status(201).json(student);
});

app.get("/api/admin/teachers", async (req, res) => {
    const context = authorize(req, res, "teachers:read");
    if (!context) return;

    const where = context.schoolId ? { schoolId: context.schoolId } : undefined;
    const teachers = await prisma.teacher.findMany({ where, orderBy: { createdAt: "desc" } });
    res.json(teachers);
});

app.post("/api/admin/teachers", validateBody(createTeacherSchema), async (req, res) => {
    const context = authorize(req, res, "teachers:write");
    if (!context) return;

    const schoolId = context.schoolId ?? req.body.schoolId;
    if (!schoolId) {
        res.status(400).json({ error: "schoolId is required" });
        return;
    }

    const teacher = await prisma.teacher.create({
        data: {
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            email: req.body.email,
            phone: req.body.phone,
            subject: req.body.subject,
            schoolId,
        },
    });
    await logAudit({
        req,
        action: "TEACHER_CREATE",
        entityType: "Teacher",
        entityId: teacher.id,
        schoolId,
        actorUserId: context.userId,
        actorRole: context.role,
        metadata: { firstName: teacher.firstName, lastName: teacher.lastName },
    });
    res.status(201).json(teacher);
});

app.get("/api/admin/classes", async (req, res) => {
    const context = authorize(req, res, "classes:read");
    if (!context) return;

    const where = context.schoolId ? { schoolId: context.schoolId } : undefined;
    const classes = await prisma.class.findMany({
        where,
        include: {
            teacher: true,
            subjects: { include: { subject: true } },
        },
        orderBy: { createdAt: "desc" },
    });
    res.json(classes);
});

app.post("/api/admin/classes", validateBody(createClassSchema), async (req, res) => {
    const context = authorize(req, res, "classes:write");
    if (!context) return;

    const schoolId = context.schoolId ?? req.body.schoolId;
    if (!schoolId) {
        res.status(400).json({ error: "schoolId is required" });
        return;
    }

    const schoolClass = await prisma.class.create({
        data: {
            name: req.body.name,
            grade: req.body.grade,
            section: req.body.section,
            academicYear: req.body.academicYear,
            schoolId,
            teacherId: req.body.teacherId,
        },
    });
    await logAudit({
        req,
        action: "CLASS_CREATE",
        entityType: "Class",
        entityId: schoolClass.id,
        schoolId,
        actorUserId: context.userId,
        actorRole: context.role,
        metadata: { name: schoolClass.name, grade: schoolClass.grade },
    });
    res.status(201).json(schoolClass);
});

app.get("/api/admin/subjects", async (req, res) => {
    const context = authorize(req, res, "subjects:read");
    if (!context) return;

    const where = context.schoolId ? { schoolId: context.schoolId } : undefined;
    const subjects = await prisma.subject.findMany({ where, orderBy: { createdAt: "desc" } });
    res.json(subjects);
});

app.post("/api/admin/subjects", validateBody(createSubjectSchema), async (req, res) => {
    const context = authorize(req, res, "subjects:write");
    if (!context) return;

    const schoolId = context.schoolId ?? req.body.schoolId;
    if (!schoolId) {
        res.status(400).json({ error: "schoolId is required" });
        return;
    }

    const subject = await prisma.subject.create({
        data: {
            name: req.body.name,
            code: req.body.code,
            description: req.body.description,
            schoolId,
        },
    });
    await logAudit({
        req,
        action: "SUBJECT_CREATE",
        entityType: "Subject",
        entityId: subject.id,
        schoolId,
        actorUserId: context.userId,
        actorRole: context.role,
        metadata: { name: subject.name, code: subject.code },
    });
    res.status(201).json(subject);
});

app.post("/api/admin/classes/:classId/subjects", async (req, res) => {
    const context = authorize(req, res, "subjects:write");
    if (!context) return;

    const link = await prisma.classSubject.create({
        data: {
            classId: req.params.classId,
            subjectId: req.body.subjectId,
        },
    });
    await logAudit({
        req,
        action: "CLASS_SUBJECT_LINK",
        entityType: "ClassSubject",
        entityId: link.id,
        schoolId: context.schoolId,
        actorUserId: context.userId,
        actorRole: context.role,
        metadata: { classId: req.params.classId, subjectId: req.body.subjectId },
    });
    res.status(201).json(link);
});

app.get("/api/admin/fees/invoices", async (req, res) => {
    const context = authorize(req, res, "fees:read");
    if (!context) return;

    const where = context.schoolId ? { schoolId: context.schoolId } : undefined;
    const invoices = await prisma.feeInvoice.findMany({
        where,
        include: { student: true, payments: true },
        orderBy: { createdAt: "desc" },
    });
    res.json(invoices);
});

app.post("/api/admin/fees/invoices", validateBody(createFeeInvoiceSchema), async (req, res) => {
    const context = authorize(req, res, "fees:write");
    if (!context) return;

    const schoolId = context.schoolId ?? req.body.schoolId;
    if (!schoolId) {
        res.status(400).json({ error: "schoolId is required" });
        return;
    }

    const invoice = await prisma.feeInvoice.create({
        data: {
            schoolId,
            studentId: req.body.studentId,
            amount: req.body.amount,
            dueDate: new Date(req.body.dueDate),
            description: req.body.description,
        },
    });
    await logAudit({
        req,
        action: "FEE_INVOICE_CREATE",
        entityType: "FeeInvoice",
        entityId: invoice.id,
        schoolId,
        actorUserId: context.userId,
        actorRole: context.role,
        metadata: { studentId: invoice.studentId, amount: Number(invoice.amount) },
    });
    res.status(201).json(invoice);
});

app.post("/api/admin/fees/payments", async (req, res) => {
    const context = authorize(req, res, "fees:write");
    if (!context) return;

    const payment = await prisma.feePayment.create({
        data: {
            invoiceId: req.body.invoiceId,
            amount: req.body.amount,
            method: req.body.method,
            reference: req.body.reference,
        },
    });

    const invoice = await prisma.feeInvoice.findUnique({
        where: { id: req.body.invoiceId },
        include: { payments: true },
    });

    if (invoice) {
        const paidAmount = invoice.payments.reduce((sum, item) => sum + Number(item.amount), 0);
        const totalAmount = Number(invoice.amount);
        const status = paidAmount >= totalAmount ? "PAID" : paidAmount > 0 ? "PARTIALLY_PAID" : "PENDING";

        await prisma.feeInvoice.update({
            where: { id: invoice.id },
            data: { status },
        });

        await logAudit({
            req,
            action: "FEE_PAYMENT_CREATE",
            entityType: "FeePayment",
            entityId: payment.id,
            schoolId: invoice.schoolId,
            actorUserId: context.userId,
            actorRole: context.role,
            metadata: {
                invoiceId: invoice.id,
                amount: Number(payment.amount),
                method: payment.method,
                updatedInvoiceStatus: status,
            },
        });
    }

    res.status(201).json(payment);
});

app.get("/api/admin/reports/overview", async (req, res) => {
    const context = authorize(req, res, "reports:read");
    if (!context) return;

    const schoolFilter = context.schoolId ? { schoolId: context.schoolId } : undefined;
    const [students, teachers, classes, subjects, invoices, paidInvoices, pendingInvoices] = await Promise.all([
        prisma.student.count({ where: schoolFilter }),
        prisma.teacher.count({ where: schoolFilter }),
        prisma.class.count({ where: schoolFilter }),
        prisma.subject.count({ where: schoolFilter }),
        prisma.feeInvoice.aggregate({
            where: schoolFilter,
            _sum: { amount: true },
        }),
        prisma.feeInvoice.aggregate({
            where: {
                ...schoolFilter,
                status: "PAID",
            },
            _sum: { amount: true },
        }),
        prisma.feeInvoice.aggregate({
            where: {
                ...schoolFilter,
                status: { in: ["PENDING", "PARTIALLY_PAID", "OVERDUE"] },
            },
            _sum: { amount: true },
        }),
    ]);

    res.json({
        students,
        teachers,
        classes,
        subjects,
        totalInvoiced: Number(invoices._sum.amount ?? 0),
        totalCollected: Number(paidInvoices._sum.amount ?? 0),
        outstandingAmount: Number(pendingInvoices._sum.amount ?? 0),
    });
});

app.get("/api/admin/users", async (req, res) => {
    const context = authorize(req, res, "reports:read");
    if (!context) return;

    const where = context.schoolId ? { schoolId: context.schoolId } : undefined;
    const users = await prisma.adminUser.findMany({ where, orderBy: { createdAt: "desc" } });
    res.json(users);
});

app.get("/api/admin/audit-logs", validateQuery(auditLogsQuerySchema), async (req, res) => {
    const context = authorize(req, res, "audit:read");
    if (!context) return;

    const query = ((req as express.Request & { validatedQuery?: Record<string, unknown> }).validatedQuery ?? req.query) as Record<string, unknown>;
    const limit = Math.min(Number(query.limit ?? 50), 200);
    const action = query.action as string | undefined;
    const status = query.status as "SUCCESS" | "FAILED" | undefined;
    const fromDate = parseDateParam(query.from);
    const toDate = parseDateParam(query.to);
    const format = (query.format as "json" | "csv" | undefined) ?? "json";

    const createdAtFilter = {
        ...(fromDate ? { gte: fromDate } : {}),
        ...(toDate ? { lte: toDate } : {}),
    };

    const where = {
        ...(context.schoolId ? { schoolId: context.schoolId } : {}),
        ...(action ? { action } : {}),
        ...(status ? { status } : {}),
        ...(fromDate || toDate ? { createdAt: createdAtFilter } : {}),
    };

    const logs = await prisma.auditLog.findMany({
        where,
        include: {
            actorUser: {
                select: {
                    id: true,
                    name: true,
                    email: true,
                    role: true,
                },
            },
        },
        orderBy: { createdAt: "desc" },
        take: Number.isNaN(limit) ? 50 : limit,
    });

    if (format === "csv") {
        const csv = buildAuditCsv(logs);
        res.setHeader("Content-Type", "text/csv; charset=utf-8");
        res.setHeader("Content-Disposition", `attachment; filename="audit-logs-${Date.now()}.csv"`);
        res.send(csv);
        return;
    }

    res.json(logs);
});

// Global error handler
app.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
    console.error("Unhandled error:", err);
    res.status(500).json({ error: "Internal server error" });
});

app.listen(port, () => {
    console.log(`Backend running on http://localhost:${port}`);
});
