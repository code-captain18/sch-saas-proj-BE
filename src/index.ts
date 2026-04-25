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
import { sendSms, generateOtp, otpExpiresAt, getGuardianPhones } from "./lib/sms.js";
import { clearLimiterKey, consumeCooldown, consumeRateLimit, getRequestIp } from "./lib/otp-security.js";
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
    createFeeStructureSchema,
    createFeeInvoiceSchema,
    generateFeeInvoicesSchema,
    auditLogsQuerySchema,
    attendanceQuerySchema,
} from "./lib/validations.js";

const app = express();
const port = Number(process.env.PORT ?? 4000);
const frontendOrigin = process.env.FRONTEND_ORIGIN ?? "http://localhost:3000";
const apiBodyLimit = process.env.API_BODY_LIMIT ?? "5mb";
const jwtSecret = process.env.JWT_SECRET ?? process.env.AUTH_JWT_SECRET ?? "dev-only-change-me";
const accessTokenTtl = "15m";
const refreshTokenTtlDays = 7;

function envPositiveInt(name: string, fallback: number) {
    const raw = process.env[name];
    if (!raw) return fallback;
    const parsed = Number.parseInt(raw, 10);
    if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
    return parsed;
}

const otpSendWindowMs = envPositiveInt("OTP_SEND_WINDOW_MS", 10 * 60 * 1000);
const otpSendCooldownMs = envPositiveInt("OTP_SEND_COOLDOWN_MS", 60 * 1000);
const otpVerifyWindowMs = envPositiveInt("OTP_VERIFY_WINDOW_MS", 10 * 60 * 1000);
const otpSendIpLimit = envPositiveInt("OTP_SEND_IP_LIMIT", 20);
const otpSendUserLimit = envPositiveInt("OTP_SEND_USER_LIMIT", 5);
const otpVerifyIpLimit = envPositiveInt("OTP_VERIFY_IP_LIMIT", 30);
const otpVerifyChallengeLimit = envPositiveInt("OTP_VERIFY_CHALLENGE_LIMIT", 5);
const otpSendIpBlockMs = envPositiveInt("OTP_SEND_IP_BLOCK_MS", 15 * 60 * 1000);
const otpSendUserBlockMs = envPositiveInt("OTP_SEND_USER_BLOCK_MS", 10 * 60 * 1000);
const otpVerifyBlockMs = envPositiveInt("OTP_VERIFY_BLOCK_MS", 15 * 60 * 1000);

const rolePermissions: Record<string, string[]> = {
    SUPER_ADMIN: ["*"],
    SCHOOL_ADMIN: [
        "schools:read",
        "schools:write",
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
    userType: "ADMIN_USER" | "TEACHER";
};

type RequestWithUser = express.Request & { authUser?: AuthUser };
type FeeLineItem = { label: string; amount: number };

function sumFeeItems(items: FeeLineItem[]) {
    return items.reduce((total, item) => total + Number(item.amount), 0);
}

function hashToken(token: string) {
    return crypto.createHash("sha256").update(token).digest("hex");
}

function createAccessToken(user: { id: string; role: Role; schoolId: string | null; userType?: "ADMIN_USER" | "TEACHER" }) {
    return jwt.sign(
        {
            sub: user.id,
            role: user.role,
            schoolId: user.schoolId,
            userType: user.userType ?? "ADMIN_USER",
        },
        jwtSecret,
        { expiresIn: accessTokenTtl },
    );
}

async function createRefreshSession(userId: string, userType: "ADMIN_USER" | "TEACHER" = "ADMIN_USER") {
    const refreshToken = crypto.randomBytes(48).toString("hex");
    const tokenHash = hashToken(refreshToken);
    const expiresAt = new Date(Date.now() + refreshTokenTtlDays * 24 * 60 * 60 * 1000);

    await prisma.authSession.create({
        data: {
            userId,
            userType,
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
        let actorUserId = params.actorUserId ?? null;
        if (actorUserId) {
            const actor = await prisma.adminUser.findUnique({ where: { id: actorUserId }, select: { id: true } });
            if (!actor) {
                actorUserId = null;
            }
        }

        await prisma.auditLog.create({
            data: {
                schoolId: params.schoolId ?? null,
                actorUserId,
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

async function getTeacherRestriction(req: RequestWithUser, schoolId: string | null) {
    if (req.authUser?.userType !== "TEACHER") {
        return null;
    }

    const teacher = await prisma.teacher.findUnique({
        where: { id: req.authUser.userId },
        select: {
            id: true,
            schoolId: true,
            subject: true,
        },
    });

    if (!teacher) {
        return {
            teacherId: req.authUser.userId,
            schoolId,
            allowedClassIds: [] as string[],
            taughtSubject: null as string | null,
            teachingAssignments: [] as Array<{ classId: string; subjectId: string }>,
        };
    }

    const assignedClasses = await prisma.class.findMany({
        where: {
            schoolId: schoolId ?? teacher.schoolId,
            OR: [{ teacherId: teacher.id }, { assistantTeacherId: teacher.id }],
        },
        select: { id: true },
    });

    const teachingAssignments = await prisma.teachingAssignment.findMany({
        where: {
            schoolId: schoolId ?? teacher.schoolId,
            teacherId: teacher.id,
        },
        select: {
            classId: true,
            subjectId: true,
        },
    });

    const explicitClassIds = teachingAssignments.map((item) => item.classId);
    const classIdSet = new Set<string>([...assignedClasses.map((item) => item.id), ...explicitClassIds]);

    return {
        teacherId: teacher.id,
        schoolId: schoolId ?? teacher.schoolId,
        allowedClassIds: [...classIdSet],
        taughtSubject: teacher.subject?.trim() || null,
        teachingAssignments,
    };
}

function hasTeacherSubjectAccess(taughtSubject: string | null, subject: { name: string; code: string }) {
    if (!taughtSubject) return true;
    const normalized = taughtSubject.toLowerCase();
    return subject.name.toLowerCase() === normalized || subject.code.toLowerCase() === normalized;
}

function hasExplicitTeachingAssignment(
    assignments: Array<{ classId: string; subjectId: string }>,
    classId: string,
    subjectId: string,
) {
    return assignments.some((item) => item.classId === classId && item.subjectId === subjectId);
}

async function validateClassTeacherAssignments(params: {
    schoolId: string;
    classIdToExclude?: string;
    teacherId?: string | null;
    assistantTeacherId?: string | null;
}) {
    const teacherId = params.teacherId?.trim() || null;
    const assistantTeacherId = params.assistantTeacherId?.trim() || null;

    if (teacherId && assistantTeacherId && teacherId === assistantTeacherId) {
        return { ok: false as const, error: "Class teacher and assistant teacher cannot be the same person" };
    }

    const selectedTeacherIds = [teacherId, assistantTeacherId].filter(Boolean) as string[];
    if (selectedTeacherIds.length === 0) {
        return { ok: true as const };
    }

    const teachersInSchool = await prisma.teacher.findMany({
        where: {
            id: { in: selectedTeacherIds },
            schoolId: params.schoolId,
        },
        select: { id: true },
    });

    if (teachersInSchool.length !== selectedTeacherIds.length) {
        return { ok: false as const, error: "Selected teacher must belong to this school" };
    }

    const conflictingClass = await prisma.class.findFirst({
        where: {
            schoolId: params.schoolId,
            ...(params.classIdToExclude ? { id: { not: params.classIdToExclude } } : {}),
            OR: [
                ...(teacherId ? [{ teacherId }, { assistantTeacherId: teacherId }] : []),
                ...(assistantTeacherId ? [{ teacherId: assistantTeacherId }, { assistantTeacherId }] : []),
            ],
        },
        select: {
            id: true,
            name: true,
            teacherId: true,
            assistantTeacherId: true,
        },
    });

    if (conflictingClass) {
        return {
            ok: false as const,
            error: `Selected teacher is already assigned to class ${conflictingClass.name}`,
        };
    }

    return { ok: true as const };
}

app.use(cors({ origin: frontendOrigin }));
app.use(express.json({ limit: apiBodyLimit }));
app.use(express.urlencoded({ extended: true, limit: apiBodyLimit }));

// Sentry request handler - must be after body parser
if (process.env.SENTRY_DSN) {
    Sentry.setupExpressErrorHandler(app);
}

app.post("/api/auth/login", validateBody(loginSchema), async (req, res) => {
    const { email, password } = req.body;

    const user = await prisma.adminUser.findUnique({ where: { email } });
    if (user) {
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

        // If admin user has a phone, require OTP (MFA)
        if (user.phone) {
            const ip = getRequestIp(req);
            const ipQuota = await consumeRateLimit(`otp-send:ip:${ip}`, {
                limit: otpSendIpLimit,
                windowMs: otpSendWindowMs,
                blockMs: otpSendIpBlockMs,
            });
            if (!ipQuota.allowed) {
                res.status(429).json({ error: `Too many OTP requests. Try again in ${ipQuota.retryAfterSeconds}s.` });
                return;
            }

            const userQuota = await consumeRateLimit(`otp-send:login:user:${user.id}`, {
                limit: otpSendUserLimit,
                windowMs: otpSendWindowMs,
                blockMs: otpSendUserBlockMs,
            });
            if (!userQuota.allowed) {
                res.status(429).json({ error: `Too many OTP requests. Try again in ${userQuota.retryAfterSeconds}s.` });
                return;
            }

            const cooldown = await consumeCooldown(`otp-send:login:user:${user.id}`, otpSendCooldownMs);
            if (!cooldown.allowed) {
                res.status(429).json({ error: `Please wait ${cooldown.retryAfterSeconds}s before requesting another OTP.` });
                return;
            }

            const otp = generateOtp();
            const otpToken = await prisma.otpToken.create({
                data: {
                    phone: user.phone,
                    code: otp,
                    purpose: "LOGIN_MFA",
                    userId: user.id,
                    userType: "ADMIN_USER",
                    expiresAt: otpExpiresAt(10),
                },
            });
            sendSms(user.phone, `Your SchoolFlow login OTP is ${otp}. It expires in 10 minutes. Do not share it with anyone.`);
            await logAudit({
                req,
                action: "AUTH_LOGIN",
                entityType: "AuthSession",
                schoolId: user.schoolId,
                actorUserId: user.id,
                actorRole: user.role as Role,
                status: "SUCCESS",
                metadata: { email, mfa: "otp_sent" },
            });
            res.json({ requiresOtp: true, challengeId: otpToken.id });
            return;
        }

        const accessToken = createAccessToken({
            id: user.id,
            role: user.role as Role,
            schoolId: user.schoolId,
            userType: "ADMIN_USER",
        });
        const refreshToken = await createRefreshSession(user.id, "ADMIN_USER");

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
        return;
    }

    const teacher = await prisma.teacher.findUnique({ where: { email } });
    if (!teacher) {
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

    if (teacher.status !== "ACTIVE") {
        await logAudit({
            req,
            action: "AUTH_LOGIN",
            entityType: "TeacherSession",
            schoolId: teacher.schoolId,
            actorRole: "STAFF",
            status: "FAILED",
            metadata: { email, reason: "teacher_inactive" },
        });
        res.status(401).json({ error: "Invalid credentials" });
        return;
    }

    const defaultTeacherPassword = process.env.DEFAULT_TEACHER_PASSWORD ?? "Teacher@123";
    let teacherPasswordHash = teacher.passwordHash;

    if (!teacherPasswordHash) {
        if (password !== defaultTeacherPassword) {
            await logAudit({
                req,
                action: "AUTH_LOGIN",
                entityType: "TeacherSession",
                schoolId: teacher.schoolId,
                actorRole: "STAFF",
                status: "FAILED",
                metadata: { email, reason: "teacher_password_not_set" },
            });
            res.status(401).json({ error: "Invalid credentials" });
            return;
        }

        teacherPasswordHash = await bcrypt.hash(defaultTeacherPassword, 10);
        await prisma.teacher.update({
            where: { id: teacher.id },
            data: { passwordHash: teacherPasswordHash },
        });
    }

    const isPasswordValid = await bcrypt.compare(password, teacherPasswordHash);
    if (!isPasswordValid) {
        await logAudit({
            req,
            action: "AUTH_LOGIN",
            entityType: "TeacherSession",
            schoolId: teacher.schoolId,
            actorRole: "STAFF",
            status: "FAILED",
            metadata: { email, reason: "invalid_password" },
        });
        res.status(401).json({ error: "Invalid credentials" });
        return;
    }

    const accessToken = createAccessToken({
        id: teacher.id,
        role: "STAFF",
        schoolId: teacher.schoolId,
        userType: "TEACHER",
    });
    const refreshToken = await createRefreshSession(teacher.id, "TEACHER");

    await logAudit({
        req,
        action: "AUTH_LOGIN",
        entityType: "TeacherSession",
        schoolId: teacher.schoolId,
        actorRole: "STAFF",
        status: "SUCCESS",
        metadata: { email },
    });

    // If teacher has a phone, require OTP (MFA)
    if (teacher.phone) {
        const ip = getRequestIp(req);
        const ipQuota = await consumeRateLimit(`otp-send:ip:${ip}`, {
            limit: otpSendIpLimit,
            windowMs: otpSendWindowMs,
            blockMs: otpSendIpBlockMs,
        });
        if (!ipQuota.allowed) {
            res.status(429).json({ error: `Too many OTP requests. Try again in ${ipQuota.retryAfterSeconds}s.` });
            return;
        }

        const userQuota = await consumeRateLimit(`otp-send:login:user:${teacher.id}`, {
            limit: otpSendUserLimit,
            windowMs: otpSendWindowMs,
            blockMs: otpSendUserBlockMs,
        });
        if (!userQuota.allowed) {
            res.status(429).json({ error: `Too many OTP requests. Try again in ${userQuota.retryAfterSeconds}s.` });
            return;
        }

        const cooldown = await consumeCooldown(`otp-send:login:user:${teacher.id}`, otpSendCooldownMs);
        if (!cooldown.allowed) {
            res.status(429).json({ error: `Please wait ${cooldown.retryAfterSeconds}s before requesting another OTP.` });
            return;
        }

        const otp = generateOtp();
        const otpToken = await prisma.otpToken.create({
            data: {
                phone: teacher.phone,
                code: otp,
                purpose: "LOGIN_MFA",
                userId: teacher.id,
                userType: "TEACHER",
                expiresAt: otpExpiresAt(10),
            },
        });
        sendSms(teacher.phone, `Your SchoolFlow login OTP is ${otp}. It expires in 10 minutes. Do not share it with anyone.`);
        res.json({ requiresOtp: true, challengeId: otpToken.id });
        return;
    }

    res.json({
        accessToken,
        refreshToken,
        user: {
            id: teacher.id,
            name: `${teacher.firstName} ${teacher.lastName}`,
            email: teacher.email,
            role: "STAFF",
            schoolId: teacher.schoolId,
        },
    });
});

app.post("/api/auth/refresh", validateBody(refreshTokenSchema), async (req, res) => {
    const { refreshToken } = req.body;

    const tokenHash = hashToken(refreshToken);
    const session = await prisma.authSession.findUnique({ where: { tokenHash } });

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

    const sessionUserType = session.userType as "ADMIN_USER" | "TEACHER";

    if (sessionUserType === "TEACHER") {
        const teacher = await prisma.teacher.findUnique({ where: { id: session.userId } });
        if (!teacher) {
            res.status(401).json({ error: "Invalid refresh token" });
            return;
        }

        const newRefreshToken = await createRefreshSession(session.userId, sessionUserType);
        const accessToken = createAccessToken({
            id: teacher.id,
            role: "STAFF",
            schoolId: teacher.schoolId,
            userType: sessionUserType,
        });

        await logAudit({
            req,
            action: "AUTH_REFRESH",
            entityType: "TeacherSession",
            schoolId: teacher.schoolId,
            actorUserId: null,
            actorRole: "STAFF",
            status: "SUCCESS",
        });

        res.json({
            accessToken,
            refreshToken: newRefreshToken,
        });
        return;
    }

    const adminUser = await prisma.adminUser.findUnique({ where: { id: session.userId } });
    if (!adminUser) {
        res.status(401).json({ error: "Invalid refresh token" });
        return;
    }

    const newRefreshToken = await createRefreshSession(session.userId, sessionUserType);
    const accessToken = createAccessToken({
        id: adminUser.id,
        role: adminUser.role as Role,
        schoolId: adminUser.schoolId,
        userType: sessionUserType,
    });

    await logAudit({
        req,
        action: "AUTH_REFRESH",
        entityType: "AuthSession",
        schoolId: adminUser.schoolId,
        actorUserId: adminUser.id,
        actorRole: adminUser.role as Role,
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
                userType: authUser.userType,
                revokedAt: null,
            },
            data: { revokedAt: new Date() },
        });
    } else {
        await prisma.authSession.updateMany({
            where: {
                userId: authUser.userId,
                userType: authUser.userType,
                revokedAt: null,
            },
            data: { revokedAt: new Date() },
        });
    }

    await logAudit({
        req,
        action: "AUTH_LOGOUT",
        entityType: authUser.userType === "TEACHER" ? "TeacherSession" : "AuthSession",
        schoolId: authUser.schoolId,
        actorUserId: authUser.userType === "TEACHER" ? null : authUser.userId,
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

    if (authUser.userType === "TEACHER") {
        const teacher = await prisma.teacher.findUnique({ where: { id: authUser.userId } });
        if (!teacher) {
            res.status(404).json({ error: "User not found" });
            return;
        }

        res.json({
            id: teacher.id,
            name: `${teacher.firstName} ${teacher.lastName}`,
            email: teacher.email,
            role: "STAFF",
            schoolId: teacher.schoolId,
        });
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

// POST /api/auth/verify-login-otp — Complete MFA login after OTP verification
app.post("/api/auth/verify-login-otp", async (req, res) => {
    const { challengeId, otp } = req.body ?? {};
    if (!challengeId || !otp) {
        res.status(400).json({ error: "challengeId and otp are required" });
        return;
    }

    const ip = getRequestIp(req);
    const ipVerifyQuota = await consumeRateLimit(`otp-verify:ip:${ip}`, {
        limit: otpVerifyIpLimit,
        windowMs: otpVerifyWindowMs,
        blockMs: otpVerifyBlockMs,
    });
    if (!ipVerifyQuota.allowed) {
        res.status(429).json({ error: `Too many OTP verification attempts. Try again in ${ipVerifyQuota.retryAfterSeconds}s.` });
        return;
    }

    const challengeQuota = await consumeRateLimit(`otp-verify:challenge:${String(challengeId)}`, {
        limit: otpVerifyChallengeLimit,
        windowMs: otpVerifyWindowMs,
        blockMs: otpVerifyBlockMs,
    });
    if (!challengeQuota.allowed) {
        res.status(429).json({ error: `Too many OTP verification attempts. Try again in ${challengeQuota.retryAfterSeconds}s.` });
        return;
    }

    const tokenRecord = await prisma.otpToken.findUnique({ where: { id: String(challengeId) } });
    if (!tokenRecord || tokenRecord.purpose !== "LOGIN_MFA") {
        res.status(400).json({ error: "Invalid OTP challenge" });
        return;
    }
    if (tokenRecord.usedAt || tokenRecord.expiresAt <= new Date()) {
        res.status(400).json({ error: "OTP has expired or already been used" });
        return;
    }
    if (tokenRecord.code !== String(otp)) {
        res.status(400).json({ error: "Invalid OTP code" });
        return;
    }

    await prisma.otpToken.update({ where: { id: tokenRecord.id }, data: { usedAt: new Date() } });
    await clearLimiterKey(`otp-verify:challenge:${String(challengeId)}`);

    if (tokenRecord.userType === "TEACHER") {
        const teacher = await prisma.teacher.findUnique({ where: { id: tokenRecord.userId! } });
        if (!teacher) {
            res.status(404).json({ error: "User not found" });
            return;
        }
        const accessToken = createAccessToken({ id: teacher.id, role: "STAFF", schoolId: teacher.schoolId, userType: "TEACHER" });
        const refreshToken = await createRefreshSession(teacher.id, "TEACHER");
        res.json({ accessToken, refreshToken, user: { id: teacher.id, name: `${teacher.firstName} ${teacher.lastName}`, email: teacher.email, role: "STAFF", schoolId: teacher.schoolId } });
        return;
    }

    const adminUser = await prisma.adminUser.findUnique({ where: { id: tokenRecord.userId! } });
    if (!adminUser) {
        res.status(404).json({ error: "User not found" });
        return;
    }
    const accessToken = createAccessToken({ id: adminUser.id, role: adminUser.role as Role, schoolId: adminUser.schoolId, userType: "ADMIN_USER" });
    const refreshToken = await createRefreshSession(adminUser.id, "ADMIN_USER");
    res.json({ accessToken, refreshToken, user: { id: adminUser.id, name: adminUser.name, email: adminUser.email, role: adminUser.role, schoolId: adminUser.schoolId } });
});

// POST /api/auth/forgot-password — Request password reset OTP via SMS
app.post("/api/auth/forgot-password", async (req, res) => {
    const { email } = req.body ?? {};
    if (!email || typeof email !== "string") {
        res.status(400).json({ error: "email is required" });
        return;
    }

    // Find user (admin or teacher) — always return 200 to avoid user enumeration
    const adminUser = await prisma.adminUser.findUnique({ where: { email } });
    const teacher = adminUser ? null : await prisma.teacher.findUnique({ where: { email } });
    const foundUser = adminUser ?? teacher;

    const ip = getRequestIp(req);
    const ipQuota = await consumeRateLimit(`otp-send:forgot:ip:${ip}`, {
        limit: otpSendIpLimit,
        windowMs: otpSendWindowMs,
        blockMs: otpSendIpBlockMs,
    });
    if (!ipQuota.allowed) {
        // Keep generic response to avoid user enumeration
        res.json({ message: "If an account with that email exists and has a phone registered, an OTP has been sent." });
        return;
    }

    if (foundUser?.phone) {
        const userQuota = await consumeRateLimit(`otp-send:forgot:user:${foundUser.id}`, {
            limit: otpSendUserLimit,
            windowMs: otpSendWindowMs,
            blockMs: otpSendUserBlockMs,
        });
        if (!userQuota.allowed) {
            res.json({ message: "If an account with that email exists and has a phone registered, an OTP has been sent." });
            return;
        }

        const cooldown = await consumeCooldown(`otp-send:forgot:user:${foundUser.id}`, otpSendCooldownMs);
        if (!cooldown.allowed) {
            res.json({ message: "If an account with that email exists and has a phone registered, an OTP has been sent." });
            return;
        }

        const otp = generateOtp();
        const userId = foundUser.id;
        const userType = adminUser ? "ADMIN_USER" : "TEACHER";
        await prisma.otpToken.create({
            data: {
                phone: foundUser.phone,
                code: otp,
                purpose: "FORGOT_PASSWORD",
                userId,
                userType,
                expiresAt: otpExpiresAt(15),
            },
        });
        sendSms(foundUser.phone, `Your SchoolFlow password reset OTP is ${otp}. It expires in 15 minutes. Do not share it with anyone.`);
    }

    res.json({ message: "If an account with that email exists and has a phone registered, an OTP has been sent." });
});

// POST /api/auth/reset-password — Reset password using OTP from forgot-password flow
app.post("/api/auth/reset-password", async (req, res) => {
    const { email, otp, newPassword } = req.body ?? {};
    if (!email || !otp || !newPassword) {
        res.status(400).json({ error: "email, otp, and newPassword are required" });
        return;
    }
    if (typeof newPassword !== "string" || newPassword.length < 8) {
        res.status(400).json({ error: "newPassword must be at least 8 characters" });
        return;
    }

    const adminUser = await prisma.adminUser.findUnique({ where: { email } });
    const teacher = adminUser ? null : await prisma.teacher.findUnique({ where: { email } });
    const foundUser = adminUser ?? teacher;

    if (!foundUser) {
        res.status(400).json({ error: "Invalid request" });
        return;
    }

    const tokenRecord = await prisma.otpToken.findFirst({
        where: {
            userId: foundUser.id,
            purpose: "FORGOT_PASSWORD",
            usedAt: null,
            expiresAt: { gt: new Date() },
        },
        orderBy: { createdAt: "desc" },
    });

    const resetQuota = await consumeRateLimit(`otp-reset:user:${foundUser.id}`, {
        limit: otpVerifyChallengeLimit,
        windowMs: otpVerifyWindowMs,
        blockMs: otpVerifyBlockMs,
    });
    if (!resetQuota.allowed) {
        res.status(429).json({ error: `Too many OTP verification attempts. Try again in ${resetQuota.retryAfterSeconds}s.` });
        return;
    }

    if (!tokenRecord || tokenRecord.code !== String(otp)) {
        res.status(400).json({ error: "Invalid or expired OTP" });
        return;
    }

    await prisma.otpToken.update({ where: { id: tokenRecord.id }, data: { usedAt: new Date() } });
    await clearLimiterKey(`otp-reset:user:${foundUser.id}`);

    const newHash = await bcrypt.hash(newPassword, 10);
    if (adminUser) {
        await prisma.adminUser.update({ where: { id: adminUser.id }, data: { passwordHash: newHash } });
    } else if (teacher) {
        await prisma.teacher.update({ where: { id: teacher.id }, data: { passwordHash: newHash } });
    }

    res.json({ message: "Password reset successfully. Please log in with your new password." });
});

// POST /api/auth/request-change-password-otp — Request OTP to change password (authenticated)
app.post("/api/auth/request-change-password-otp", authenticate, async (req: RequestWithUser, res) => {
    const authUser = req.authUser;
    if (!authUser) {
        res.status(401).json({ error: "Unauthorized" });
        return;
    }

    let phone: string | null = null;
    if (authUser.userType === "TEACHER") {
        const teacher = await prisma.teacher.findUnique({ where: { id: authUser.userId }, select: { phone: true } });
        phone = teacher?.phone ?? null;
    } else {
        const adminUser = await prisma.adminUser.findUnique({ where: { id: authUser.userId }, select: { phone: true } });
        phone = adminUser?.phone ?? null;
    }

    if (!phone) {
        res.status(400).json({ error: "No phone number is registered on this account. Contact your administrator." });
        return;
    }

    const ip = getRequestIp(req);
    const ipQuota = await consumeRateLimit(`otp-send:change:ip:${ip}`, {
        limit: otpSendIpLimit,
        windowMs: otpSendWindowMs,
        blockMs: otpSendIpBlockMs,
    });
    if (!ipQuota.allowed) {
        res.status(429).json({ error: `Too many OTP requests. Try again in ${ipQuota.retryAfterSeconds}s.` });
        return;
    }

    const userQuota = await consumeRateLimit(`otp-send:change:user:${authUser.userId}`, {
        limit: otpSendUserLimit,
        windowMs: otpSendWindowMs,
        blockMs: otpSendUserBlockMs,
    });
    if (!userQuota.allowed) {
        res.status(429).json({ error: `Too many OTP requests. Try again in ${userQuota.retryAfterSeconds}s.` });
        return;
    }

    const cooldown = await consumeCooldown(`otp-send:change:user:${authUser.userId}`, otpSendCooldownMs);
    if (!cooldown.allowed) {
        res.status(429).json({ error: `Please wait ${cooldown.retryAfterSeconds}s before requesting another OTP.` });
        return;
    }

    const otp = generateOtp();
    const otpToken = await prisma.otpToken.create({
        data: {
            phone,
            code: otp,
            purpose: "CHANGE_PASSWORD",
            userId: authUser.userId,
            userType: authUser.userType,
            expiresAt: otpExpiresAt(10),
        },
    });
    sendSms(phone, `Your SchoolFlow OTP for changing your password is ${otp}. It expires in 10 minutes. Do not share it with anyone.`);
    res.json({ challengeId: otpToken.id, message: "OTP sent to your registered phone number." });
});

// POST /api/auth/change-password — Change password using OTP (authenticated)
app.post("/api/auth/change-password", authenticate, async (req: RequestWithUser, res) => {
    const authUser = req.authUser;
    if (!authUser) {
        res.status(401).json({ error: "Unauthorized" });
        return;
    }

    const { challengeId, otp, newPassword } = req.body ?? {};
    if (!challengeId || !otp || !newPassword) {
        res.status(400).json({ error: "challengeId, otp, and newPassword are required" });
        return;
    }
    if (typeof newPassword !== "string" || newPassword.length < 8) {
        res.status(400).json({ error: "newPassword must be at least 8 characters" });
        return;
    }

    const challengeQuota = await consumeRateLimit(`otp-change:challenge:${String(challengeId)}`, {
        limit: otpVerifyChallengeLimit,
        windowMs: otpVerifyWindowMs,
        blockMs: otpVerifyBlockMs,
    });
    if (!challengeQuota.allowed) {
        res.status(429).json({ error: `Too many OTP verification attempts. Try again in ${challengeQuota.retryAfterSeconds}s.` });
        return;
    }

    const tokenRecord = await prisma.otpToken.findUnique({ where: { id: String(challengeId) } });
    if (!tokenRecord || tokenRecord.purpose !== "CHANGE_PASSWORD" || tokenRecord.userId !== authUser.userId) {
        res.status(400).json({ error: "Invalid OTP challenge" });
        return;
    }
    if (tokenRecord.usedAt || tokenRecord.expiresAt <= new Date()) {
        res.status(400).json({ error: "OTP has expired or already been used" });
        return;
    }
    if (tokenRecord.code !== String(otp)) {
        res.status(400).json({ error: "Invalid OTP code" });
        return;
    }

    await prisma.otpToken.update({ where: { id: tokenRecord.id }, data: { usedAt: new Date() } });
    await clearLimiterKey(`otp-change:challenge:${String(challengeId)}`);

    const newHash = await bcrypt.hash(newPassword, 10);
    if (authUser.userType === "TEACHER") {
        await prisma.teacher.update({ where: { id: authUser.userId }, data: { passwordHash: newHash } });
    } else {
        await prisma.adminUser.update({ where: { id: authUser.userId }, data: { passwordHash: newHash } });
    }

    res.json({ message: "Password changed successfully." });
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
app.use("/api/staff", authenticate);

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

    // Build guardianInfo JSON from form fields
    const guardianInfo: any = {};

    const fatherData = {
        firstName: req.body.fatherFirstName,
        lastName: req.body.fatherLastName,
        phone: req.body.fatherPhone,
        email: req.body.fatherEmail,
        occupation: req.body.fatherOccupation,
        residentialAddress: req.body.fatherResidentialAddress,
        postalAddress: req.body.fatherPostalAddress,
    };

    if (fatherData.firstName || fatherData.lastName) {
        guardianInfo.father = Object.fromEntries(
            Object.entries(fatherData).filter(([, value]) => value)
        );
    }

    const motherAddressSameAsFather = req.body.motherAddressSameAsFather === 'true';
    const motherData = {
        firstName: req.body.motherFirstName,
        lastName: req.body.motherLastName,
        phone: req.body.motherPhone,
        email: req.body.motherEmail,
        occupation: req.body.motherOccupation,
        residentialAddress: motherAddressSameAsFather ? req.body.fatherResidentialAddress : req.body.motherResidentialAddress,
        postalAddress: motherAddressSameAsFather ? req.body.fatherPostalAddress : req.body.motherPostalAddress,
    };

    if (motherData.firstName || motherData.lastName) {
        guardianInfo.mother = Object.fromEntries(
            Object.entries(motherData).filter(([, value]) => value)
        );
    }

    const student = await prisma.student.create({
        data: {
            firstName: req.body.firstName,
            otherNames: req.body.otherNames,
            lastName: req.body.lastName,
            gender: req.body.gender,
            email: req.body.email,
            dateOfBirth: new Date(req.body.dateOfBirth),
            previousSchool: req.body.previousSchool,
            picture: req.body.picture,
            medicalCondition: req.body.medicalCondition,
            allergies: req.body.allergies,
            guardianInfo: Object.keys(guardianInfo).length > 0 ? guardianInfo : null,
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
        metadata: { firstName: student.firstName, lastName: student.lastName, gender: req.body.gender },
    });

    // Notify guardian(s) via SMS
    const guardianPhones = getGuardianPhones(student.guardianInfo);
    const studentName = [student.firstName, student.lastName].filter(Boolean).join(" ");
    for (const phone of guardianPhones) {
        sendSms(phone, `Dear Guardian, ${studentName} has been successfully enrolled at your school on SchoolFlow. Contact the school for further details.`);
    }

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

    const defaultTeacherPasswordHash = await bcrypt.hash(process.env.DEFAULT_TEACHER_PASSWORD ?? "Teacher@123", 10);

    const teacher = await prisma.teacher.create({
        data: {
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            otherNames: req.body.otherNames || null,
            dateOfBirth: req.body.dateOfBirth ? new Date(req.body.dateOfBirth) : null,
            ssnitNumber: req.body.ssnitNumber,
            educationalLevel: req.body.educationalLevel,
            certifications: req.body.certifications || null,
            picture: req.body.picture || null,
            maritalStatus: req.body.maritalStatus,
            nextOfKin: req.body.nextOfKin,
            nextOfKinRelationship: req.body.nextOfKinRelationship,
            residentialAddress: req.body.residentialAddress,
            email: req.body.email,
            passwordHash: defaultTeacherPasswordHash,
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
            assistantTeacher: true,
            prefectStudent: {
                select: {
                    id: true,
                    firstName: true,
                    otherNames: true,
                    lastName: true,
                },
            },
            assistantPrefectStudent: {
                select: {
                    id: true,
                    firstName: true,
                    otherNames: true,
                    lastName: true,
                },
            },
            subjects: { include: { subject: true } },
            teachingAssignments: {
                include: {
                    teacher: {
                        select: {
                            id: true,
                            firstName: true,
                            lastName: true,
                        },
                    },
                    subject: {
                        select: {
                            id: true,
                            name: true,
                            code: true,
                        },
                    },
                },
            },
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

    const teacherAssignmentValidation = await validateClassTeacherAssignments({
        schoolId,
        teacherId: req.body.teacherId,
        assistantTeacherId: req.body.assistantTeacherId,
    });
    if (!teacherAssignmentValidation.ok) {
        res.status(400).json({ error: teacherAssignmentValidation.error });
        return;
    }

    const schoolClass = await prisma.class.create({
        data: {
            name: req.body.name,
            grade: req.body.grade,
            section: req.body.section,
            academicYear: req.body.academicYear,
            feeAmount: req.body.feeAmount,
            schoolId,
            teacherId: req.body.teacherId,
            assistantTeacherId: req.body.assistantTeacherId,
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
        metadata: { name: schoolClass.name, grade: schoolClass.grade, feeAmount: schoolClass.feeAmount ? Number(schoolClass.feeAmount) : null },
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
            groupName: req.body.groupName || null,
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

app.post("/api/admin/subjects/bulk-assign", async (req, res) => {
    const context = authorize(req, res, "subjects:write");
    if (!context) return;

    const subjectIds = Array.isArray(req.body.subjectIds) ? req.body.subjectIds.map((value: unknown) => String(value)) : [];
    const classIds = Array.isArray(req.body.classIds) ? req.body.classIds.map((value: unknown) => String(value)) : [];

    if (subjectIds.length === 0 || classIds.length === 0) {
        res.status(400).json({ error: "subjectIds and classIds are required" });
        return;
    }

    const whereSchool = context.schoolId ? { schoolId: context.schoolId } : undefined;

    const [subjectsInScope, classesInScope] = await Promise.all([
        prisma.subject.findMany({ where: { id: { in: subjectIds }, ...(whereSchool ?? {}) }, select: { id: true } }),
        prisma.class.findMany({ where: { id: { in: classIds }, ...(whereSchool ?? {}) }, select: { id: true } }),
    ]);

    if (subjectsInScope.length !== subjectIds.length || classesInScope.length !== classIds.length) {
        res.status(400).json({ error: "One or more selected classes/subjects are invalid for this school" });
        return;
    }

    const data = classesInScope.flatMap((schoolClass) =>
        subjectsInScope.map((subject) => ({
            classId: schoolClass.id,
            subjectId: subject.id,
        })),
    );

    await prisma.classSubject.createMany({
        data,
        skipDuplicates: true,
    });

    await logAudit({
        req,
        action: "CLASS_SUBJECT_BULK_ASSIGN",
        entityType: "ClassSubject",
        schoolId: context.schoolId,
        actorUserId: context.userId,
        actorRole: context.role,
        metadata: { subjectIds, classIds, combinations: data.length },
    });

    res.status(201).json({ ok: true, createdCombinations: data.length });
});

app.get("/api/admin/teaching-assignments", async (req, res) => {
    const context = authorize(req, res, "teachers:read");
    if (!context) return;

    const where = context.schoolId ? { schoolId: context.schoolId } : undefined;
    const assignments = await prisma.teachingAssignment.findMany({
        where,
        include: {
            teacher: {
                select: { id: true, firstName: true, lastName: true, email: true },
            },
            class: {
                select: { id: true, name: true, grade: true, section: true },
            },
            subject: {
                select: { id: true, name: true, code: true, groupName: true },
            },
        },
        orderBy: { createdAt: "desc" },
    });

    res.json(assignments);
});

app.post("/api/admin/teaching-assignments", async (req, res) => {
    const context = authorize(req, res, "teachers:write");
    if (!context) return;

    const teacherId = String(req.body.teacherId || "");
    const classId = String(req.body.classId || "");
    const subjectId = String(req.body.subjectId || "");
    if (!teacherId || !classId || !subjectId) {
        res.status(400).json({ error: "teacherId, classId and subjectId are required" });
        return;
    }

    const whereSchool = context.schoolId ? { schoolId: context.schoolId } : undefined;
    const [teacher, schoolClass, subject] = await Promise.all([
        prisma.teacher.findFirst({ where: { id: teacherId, ...(whereSchool ?? {}) }, select: { id: true, schoolId: true } }),
        prisma.class.findFirst({ where: { id: classId, ...(whereSchool ?? {}) }, select: { id: true, schoolId: true } }),
        prisma.subject.findFirst({ where: { id: subjectId, ...(whereSchool ?? {}) }, select: { id: true, schoolId: true } }),
    ]);

    if (!teacher || !schoolClass || !subject) {
        res.status(400).json({ error: "Teacher, class, or subject is invalid for this school" });
        return;
    }

    const classSubjectLink = await prisma.classSubject.findUnique({
        where: {
            classId_subjectId: {
                classId,
                subjectId,
            },
        },
        select: { id: true },
    });

    if (!classSubjectLink) {
        res.status(400).json({ error: "Subject is not assigned to the selected class" });
        return;
    }

    const assignmentSchoolId = context.schoolId ?? teacher.schoolId;

    const assignment = await prisma.teachingAssignment.upsert({
        where: {
            teacherId_classId_subjectId: {
                teacherId,
                classId,
                subjectId,
            },
        },
        update: {},
        create: {
            schoolId: assignmentSchoolId,
            teacherId,
            classId,
            subjectId,
        },
        include: {
            teacher: {
                select: { id: true, firstName: true, lastName: true, email: true },
            },
            class: {
                select: { id: true, name: true, grade: true, section: true },
            },
            subject: {
                select: { id: true, name: true, code: true, groupName: true },
            },
        },
    });

    await logAudit({
        req,
        action: "TEACHING_ASSIGNMENT_CREATE",
        entityType: "TeachingAssignment",
        entityId: assignment.id,
        schoolId: assignmentSchoolId,
        actorUserId: context.userId,
        actorRole: context.role,
        metadata: { teacherId, classId, subjectId },
    });

    res.status(201).json(assignment);
});

app.delete("/api/admin/teaching-assignments/:id", async (req, res) => {
    const context = authorize(req, res, "teachers:write");
    if (!context) return;

    const existing = await prisma.teachingAssignment.findUnique({ where: { id: req.params.id } });
    if (!existing) {
        res.status(404).json({ error: "Teaching assignment not found" });
        return;
    }
    if (context.schoolId && existing.schoolId !== context.schoolId) {
        res.status(403).json({ error: "Forbidden" });
        return;
    }

    await prisma.teachingAssignment.delete({ where: { id: req.params.id } });
    await logAudit({
        req,
        action: "TEACHING_ASSIGNMENT_DELETE",
        entityType: "TeachingAssignment",
        entityId: req.params.id,
        schoolId: existing.schoolId,
        actorUserId: context.userId,
        actorRole: context.role,
        metadata: { teacherId: existing.teacherId, classId: existing.classId, subjectId: existing.subjectId },
    });

    res.json({ ok: true });
});

app.get("/api/admin/fees/invoices", async (req, res) => {
    const context = authorize(req, res, "fees:read");
    if (!context) return;

    const where = context.schoolId ? { schoolId: context.schoolId } : undefined;
    const invoices = await prisma.feeInvoice.findMany({
        where,
        include: {
            student: {
                include: {
                    class: true,
                },
            },
            feeStructure: {
                include: {
                    class: true,
                },
            },
            payments: true,
        },
        orderBy: { createdAt: "desc" },
    });
    res.json(invoices);
});

app.get("/api/admin/fees/structures", async (req, res) => {
    const context = authorize(req, res, "fees:read");
    if (!context) return;

    const where = context.schoolId ? { schoolId: context.schoolId } : undefined;
    const structures = await prisma.feeStructure.findMany({
        where,
        include: {
            class: true,
        },
        orderBy: [{ academicYear: "desc" }, { term: "asc" }, { createdAt: "desc" }],
    });

    res.json(structures);
});

app.post("/api/admin/fees/structures", validateBody(createFeeStructureSchema), async (req, res) => {
    const context = authorize(req, res, "fees:write");
    if (!context) return;

    const schoolId = context.schoolId ?? req.body.schoolId;
    if (!schoolId) {
        res.status(400).json({ error: "schoolId is required" });
        return;
    }

    if (req.body.classId) {
        const schoolClass = await prisma.class.findUnique({ where: { id: req.body.classId } });
        if (!schoolClass || schoolClass.schoolId !== schoolId) {
            res.status(400).json({ error: "Selected class does not belong to this school" });
            return;
        }
    }

    const items = req.body.items as FeeLineItem[];
    const totalAmount = sumFeeItems(items);

    const structure = await prisma.feeStructure.create({
        data: {
            schoolId,
            title: req.body.title,
            academicYear: req.body.academicYear,
            term: req.body.term,
            scopeType: req.body.scopeType,
            classId: req.body.scopeType === "CLASS" ? req.body.classId : null,
            grade: req.body.scopeType === "GRADE" ? req.body.grade : null,
            items,
            totalAmount,
        },
        include: {
            class: true,
        },
    });

    await logAudit({
        req,
        action: "FEE_STRUCTURE_CREATE",
        entityType: "FeeStructure",
        entityId: structure.id,
        schoolId,
        actorUserId: context.userId,
        actorRole: context.role,
        metadata: {
            title: structure.title,
            term: structure.term,
            scopeType: structure.scopeType,
            classId: structure.classId,
            grade: structure.grade,
            totalAmount: Number(structure.totalAmount),
        },
    });

    res.status(201).json(structure);
});

app.post("/api/admin/fees/invoices", validateBody(createFeeInvoiceSchema), async (req, res) => {
    const context = authorize(req, res, "fees:write");
    if (!context) return;

    const schoolId = context.schoolId ?? req.body.schoolId;
    if (!schoolId) {
        res.status(400).json({ error: "schoolId is required" });
        return;
    }

    const student = await prisma.student.findUnique({ where: { id: req.body.studentId } });
    if (!student || student.schoolId !== schoolId) {
        res.status(400).json({ error: "Student does not belong to this school" });
        return;
    }

    let feeStructureId: string | null = null;
    if (req.body.feeStructureId) {
        const structure = await prisma.feeStructure.findUnique({ where: { id: req.body.feeStructureId } });
        if (!structure || structure.schoolId !== schoolId) {
            res.status(400).json({ error: "Fee structure does not belong to this school" });
            return;
        }
        feeStructureId = structure.id;
    }

    const lineItems = (req.body.lineItems ?? null) as FeeLineItem[] | null;
    const amount = req.body.amount ?? (lineItems ? sumFeeItems(lineItems) : 0);

    const invoice = await prisma.feeInvoice.create({
        data: {
            schoolId,
            studentId: req.body.studentId,
            amount,
            term: req.body.term,
            academicYear: req.body.academicYear,
            dueDate: new Date(req.body.dueDate),
            description: req.body.description,
            ...(lineItems ? { lineItems } : {}),
            feeStructureId,
        },
        include: {
            student: {
                include: {
                    class: true,
                },
            },
            feeStructure: {
                include: {
                    class: true,
                },
            },
            payments: true,
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
        metadata: {
            studentId: invoice.studentId,
            amount: Number(invoice.amount),
            term: invoice.term,
            academicYear: invoice.academicYear,
            feeStructureId: invoice.feeStructureId,
        },
    });

    // Notify guardian(s) via SMS
    const invoiceGuardianPhones = getGuardianPhones(invoice.student.guardianInfo);
    const invoiceStudentName = [invoice.student.firstName, invoice.student.lastName].filter(Boolean).join(" ");
    const invoiceDue = invoice.dueDate.toLocaleDateString("en-GB");
    for (const phone of invoiceGuardianPhones) {
        sendSms(phone, `Dear Guardian, a fee invoice of GHS ${Number(invoice.amount).toFixed(2)} has been raised for ${invoiceStudentName} (${invoice.term.replace("_", " ")}, ${invoice.academicYear ?? ""}). Due: ${invoiceDue}. Contact the school for details.`);
    }

    res.status(201).json(invoice);
});

app.post("/api/admin/fees/invoices/generate", validateBody(generateFeeInvoicesSchema), async (req, res) => {
    const context = authorize(req, res, "fees:write");
    if (!context) return;

    const structure = await prisma.feeStructure.findUnique({
        where: { id: req.body.feeStructureId },
        include: {
            class: true,
        },
    });

    if (!structure) {
        res.status(404).json({ error: "Fee structure not found" });
        return;
    }

    if (context.schoolId && structure.schoolId !== context.schoolId) {
        res.status(403).json({ error: "Forbidden" });
        return;
    }

    const studentWhere: Prisma.StudentWhereInput = {
        schoolId: structure.schoolId,
        status: "ACTIVE",
        ...(structure.scopeType === "CLASS"
            ? { classId: structure.classId }
            : { class: { is: { grade: structure.grade ?? undefined } } }),
    };

    const students = await prisma.student.findMany({
        where: studentWhere,
        include: {
            class: true,
        },
    });

    if (students.length === 0) {
        res.status(400).json({ error: "No students found for the selected fee scope" });
        return;
    }

    const existingInvoices = await prisma.feeInvoice.findMany({
        where: {
            feeStructureId: structure.id,
            studentId: { in: students.map((student) => student.id) },
        },
        select: { studentId: true },
    });

    const existingStudentIds = new Set(existingInvoices.map((invoice) => invoice.studentId));
    const lineItems = structure.items as FeeLineItem[];
    const description = req.body.description ?? `${structure.title} (${structure.term.replace("_", " ")})`;

    const createdInvoices = await prisma.$transaction(
        students
            .filter((student) => !existingStudentIds.has(student.id))
            .map((student) =>
                prisma.feeInvoice.create({
                    data: {
                        schoolId: structure.schoolId,
                        studentId: student.id,
                        amount: structure.totalAmount,
                        term: structure.term,
                        academicYear: structure.academicYear,
                        dueDate: new Date(req.body.dueDate),
                        description,
                        lineItems,
                        feeStructureId: structure.id,
                    },
                    include: {
                        student: {
                            include: {
                                class: true,
                            },
                        },
                        feeStructure: {
                            include: {
                                class: true,
                            },
                        },
                        payments: true,
                    },
                }),
            ),
    );

    await logAudit({
        req,
        action: "FEE_INVOICE_BULK_GENERATE",
        entityType: "FeeStructure",
        entityId: structure.id,
        schoolId: structure.schoolId,
        actorUserId: context.userId,
        actorRole: context.role,
        metadata: {
            createdCount: createdInvoices.length,
            skippedCount: students.length - createdInvoices.length,
            term: structure.term,
            academicYear: structure.academicYear,
            scopeType: structure.scopeType,
            classId: structure.classId,
            grade: structure.grade,
        },
    });

    // Notify each guardian via SMS (fire-and-forget)
    const bulkDue = new Date(req.body.dueDate).toLocaleDateString("en-GB");
    for (const inv of createdInvoices) {
        const phones = getGuardianPhones(inv.student.guardianInfo);
        const sName = [inv.student.firstName, inv.student.lastName].filter(Boolean).join(" ");
        for (const phone of phones) {
            sendSms(phone, `Dear Guardian, a fee invoice of GHS ${Number(inv.amount).toFixed(2)} has been raised for ${sName} (${structure.term.replace("_", " ")}, ${structure.academicYear}). Due: ${bulkDue}. Contact the school for details.`);
        }
    }

    res.status(201).json({
        createdCount: createdInvoices.length,
        skippedCount: students.length - createdInvoices.length,
        invoices: createdInvoices,
    });
});

app.post("/api/admin/fees/payments", async (req, res) => {
    const context = authorize(req, res, "fees:write");
    if (!context) return;

    const invoiceId = typeof req.body.invoiceId === "string" ? req.body.invoiceId : "";
    const paymentAmount = Number(req.body.amount);
    const method = typeof req.body.method === "string" ? req.body.method : "";
    const reference = typeof req.body.reference === "string" ? req.body.reference : undefined;

    if (!invoiceId) {
        res.status(400).json({ error: "invoiceId is required" });
        return;
    }

    if (!Number.isFinite(paymentAmount) || paymentAmount <= 0) {
        res.status(400).json({ error: "amount must be a positive number" });
        return;
    }

    const validMethods = ["CASH", "BANK_TRANSFER", "CARD", "ONLINE"] as const;
    if (!validMethods.includes(method as (typeof validMethods)[number])) {
        res.status(400).json({ error: "method must be one of CASH, BANK_TRANSFER, CARD, ONLINE" });
        return;
    }

    const paymentMethod = method as (typeof validMethods)[number];

    const existingInvoice = await prisma.feeInvoice.findUnique({
        where: { id: invoiceId },
        include: { payments: true },
    });

    if (!existingInvoice) {
        res.status(404).json({ error: "Invoice not found" });
        return;
    }

    if (context.schoolId && existingInvoice.schoolId !== context.schoolId) {
        res.status(403).json({ error: "Forbidden" });
        return;
    }

    const paidSoFar = existingInvoice.payments.reduce((sum, item) => sum + Number(item.amount), 0);
    const totalInvoiceAmount = Number(existingInvoice.amount);
    const nextPaidAmount = paidSoFar + paymentAmount;

    if (nextPaidAmount > totalInvoiceAmount) {
        res.status(400).json({
            error: "Payment exceeds outstanding balance",
            details: {
                totalAmount: totalInvoiceAmount,
                paidAmount: paidSoFar,
                outstandingAmount: Math.max(totalInvoiceAmount - paidSoFar, 0),
            },
        });
        return;
    }

    const payment = await prisma.feePayment.create({
        data: {
            invoiceId,
            amount: paymentAmount,
            method: paymentMethod,
            reference,
        },
    });

    const invoice = await prisma.feeInvoice.findUnique({
        where: { id: invoiceId },
        include: {
            payments: true,
            student: {
                include: {
                    class: true,
                },
            },
            feeStructure: {
                include: {
                    class: true,
                },
            },
        },
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

    res.status(201).json({
        payment,
        invoice,
    });
});

app.get("/api/admin/reports/overview", async (req, res) => {
    const context = authorize(req, res, "reports:read");
    if (!context) return;

    const schoolFilter = context.schoolId ? { schoolId: context.schoolId } : undefined;
    const [students, teachers, classes, subjects, invoices, payments] = await Promise.all([
        prisma.student.count({ where: schoolFilter }),
        prisma.teacher.count({ where: schoolFilter }),
        prisma.class.count({ where: schoolFilter }),
        prisma.subject.count({ where: schoolFilter }),
        prisma.feeInvoice.aggregate({
            where: schoolFilter,
            _sum: { amount: true },
        }),
        prisma.feePayment.aggregate({
            where: schoolFilter ? { invoice: { schoolId: schoolFilter.schoolId } } : undefined,
            _sum: { amount: true },
        }),
    ]);

    const totalInvoiced = Number(invoices._sum.amount ?? 0);
    const totalCollected = Number(payments._sum.amount ?? 0);
    const outstandingAmount = Math.max(totalInvoiced - totalCollected, 0);

    res.json({
        students,
        teachers,
        classes,
        subjects,
        totalInvoiced,
        totalCollected,
        outstandingAmount,
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

app.get("/api/admin/attendance", validateQuery(attendanceQuerySchema), async (req, res) => {
    const context = authorize(req, res, "students:read");
    if (!context) return;

    try {
        const query = ((req as express.Request & { validatedQuery?: Record<string, unknown> }).validatedQuery ?? req.query) as Record<string, unknown>;
        const classId = typeof query.classId === "string" ? query.classId : undefined;
        const fromDate = parseDateParam(query.from);
        const toDate = parseDateParam(query.to);
        const toDateInclusive = toDate ? new Date(toDate) : null;

        if (toDateInclusive) {
            toDateInclusive.setHours(23, 59, 59, 999);
        }

        const attendance = await prisma.attendance.findMany({
            where: {
                ...(context.schoolId ? { schoolId: context.schoolId } : {}),
                ...(classId ? { classId } : {}),
                ...(fromDate || toDate
                    ? {
                        date: {
                            ...(fromDate ? { gte: fromDate } : {}),
                            ...(toDateInclusive ? { lte: toDateInclusive } : {}),
                        },
                    }
                    : {}),
            },
            include: {
                student: {
                    select: {
                        id: true,
                        firstName: true,
                        lastName: true,
                        otherNames: true,
                        email: true,
                    },
                },
                class: {
                    select: {
                        id: true,
                        name: true,
                        grade: true,
                        section: true,
                    },
                },
            },
            orderBy: [
                { date: "desc" },
                { createdAt: "desc" },
            ],
        });

        res.json(attendance);
    } catch (error) {
        console.error("Failed to get admin attendance:", error);
        res.status(500).json({ error: "Failed to get attendance" });
    }
});

// ============================================================================
// STAFF ENDPOINTS
// ============================================================================

// GET /api/staff/attendance - Get attendance records for staff member's classes
app.get("/api/staff/attendance", async (req: RequestWithUser, res) => {
    const context = authorize(req, res, "students:read");
    if (!context) return;

    try {
        const restriction = await getTeacherRestriction(req, context.schoolId);
        if (restriction && restriction.allowedClassIds.length === 0) {
            res.json([]);
            return;
        }

        const attendance = await prisma.attendance.findMany({
            where: {
                schoolId: context.schoolId ?? "",
                ...(restriction ? { classId: { in: restriction.allowedClassIds } } : {}),
            },
            include: {
                student: {
                    select: {
                        id: true,
                        firstName: true,
                        lastName: true,
                        email: true,
                    },
                },
                class: {
                    select: {
                        id: true,
                        name: true,
                        grade: true,
                    },
                },
            },
            orderBy: { date: "desc" },
            take: 100,
        });

        res.json(attendance);
    } catch (error) {
        console.error("Failed to get attendance:", error);
        res.status(500).json({ error: "Failed to get attendance" });
    }
});

// POST /api/staff/attendance - Mark attendance
app.post("/api/staff/attendance", async (req: RequestWithUser, res) => {
    const context = authorize(req, res, "students:read");
    if (!context) return;
    if (context.role === "VIEWER") {
        return res.status(403).json({ error: "Forbidden: insufficient role permissions" });
    }

    try {
        const { studentId, classId, date, status, remarks } = req.body;

        if (!studentId || !classId || !date || !status) {
            return res.status(400).json({ error: "Missing required fields" });
        }

        // Ensure attendance is only marked for today
        const submittedDate = new Date(date).toISOString().split("T")[0];
        const today = new Date().toISOString().split("T")[0];
        if (submittedDate !== today) {
            return res.status(400).json({ error: "Attendance can only be marked for today" });
        }

        const restriction = await getTeacherRestriction(req, context.schoolId);
        if (restriction && !restriction.allowedClassIds.includes(String(classId))) {
            return res.status(403).json({ error: "Forbidden: class not assigned to this teacher" });
        }

        const studentRecord = await prisma.student.findFirst({
            where: {
                id: String(studentId),
                schoolId: context.schoolId ?? "",
                classId: String(classId),
            },
            select: { id: true, firstName: true, lastName: true, guardianInfo: true },
        });

        if (!studentRecord) {
            return res.status(400).json({ error: "Student is not enrolled in the selected class" });
        }

        const attendance = await prisma.attendance.upsert({
            where: {
                studentId_classId_date: {
                    studentId: String(studentId),
                    classId: String(classId),
                    date: new Date(date),
                },
            },
            create: {
                schoolId: context.schoolId ?? "",
                studentId: String(studentId),
                classId: String(classId),
                date: new Date(date),
                status,
                remarks: remarks ? String(remarks) : undefined,
            },
            update: {
                status,
                remarks: remarks ? String(remarks) : undefined,
            },
        });

        await logAudit({
            req,
            action: "ATTENDANCE_MARK",
            entityType: "Attendance",
            entityId: attendance.id,
            schoolId: context.schoolId,
            actorUserId: context.userId,
            actorRole: context.role,
            status: "SUCCESS",
            metadata: { studentId: String(studentId), classId: String(classId), date, status },
        });

        // Notify guardian(s) when student is marked absent
        if (String(status).toUpperCase() === "ABSENT") {
            const absentStudentName = [studentRecord.firstName, studentRecord.lastName].filter(Boolean).join(" ");
            const absentDate = new Date(date).toLocaleDateString("en-GB");
            const absentPhones = getGuardianPhones(studentRecord.guardianInfo);
            for (const phone of absentPhones) {
                sendSms(phone, `Dear Guardian, ${absentStudentName} was marked ABSENT from school on ${absentDate}. Please contact the school if this is unexpected.`);
            }
        }

        res.status(201).json(attendance);
    } catch (error) {
        console.error("Failed to mark attendance:", error);
        res.status(500).json({ error: "Failed to mark attendance" });
    }
});

// PATCH /api/staff/attendance/:id - Update attendance
app.patch("/api/staff/attendance/:id", async (req: RequestWithUser, res) => {
    const context = authorize(req, res, "students:read");
    if (!context) return;
    if (context.role === "VIEWER") {
        return res.status(403).json({ error: "Forbidden: insufficient role permissions" });
    }

    try {
        const id = String(req.params.id);
        const { status, remarks } = req.body;

        const existing = await prisma.attendance.findUnique({
            where: { id },
            select: { id: true, classId: true, schoolId: true },
        });

        if (!existing || existing.schoolId !== (context.schoolId ?? "")) {
            return res.status(404).json({ error: "Attendance record not found" });
        }

        const restriction = await getTeacherRestriction(req, context.schoolId);
        if (restriction && !restriction.allowedClassIds.includes(existing.classId)) {
            return res.status(403).json({ error: "Forbidden: class not assigned to this teacher" });
        }

        const updated = await prisma.attendance.update({
            where: { id: String(id) },
            data: {
                ...(status ? { status } : {}),
                ...(remarks ? { remarks: String(remarks) } : {}),
            },
        });

        await logAudit({
            req,
            action: "ATTENDANCE_UPDATE",
            entityType: "Attendance",
            entityId: id,
            schoolId: context.schoolId,
            actorUserId: context.userId,
            actorRole: context.role,
            status: "SUCCESS",
            metadata: { status: status ? String(status) : undefined, remarks: remarks ? String(remarks) : undefined },
        });

        res.json(updated);
    } catch (error) {
        console.error("Failed to update attendance:", error);
        res.status(500).json({ error: "Failed to update attendance" });
    }
});

// GET /api/staff/scores - Get scores for a class
app.get("/api/staff/scores", async (req: RequestWithUser, res) => {
    const context = authorize(req, res, "students:read");
    if (!context) return;

    try {
        const classId = typeof req.query.classId === "string" ? req.query.classId : undefined;
        const restriction = await getTeacherRestriction(req, context.schoolId);

        if (restriction && restriction.allowedClassIds.length === 0) {
            res.json([]);
            return;
        }

        if (restriction && classId && !restriction.allowedClassIds.includes(classId)) {
            return res.status(403).json({ error: "Forbidden: class not assigned to this teacher" });
        }

        const where: Prisma.ScoreWhereInput = {
            schoolId: context.schoolId ?? "",
            ...(classId ? { classId } : {}),
            ...(restriction ? { classId: { in: classId ? [classId] : restriction.allowedClassIds } } : {}),
            ...(restriction?.taughtSubject
                ? {
                    subject: {
                        OR: [
                            { name: { equals: restriction.taughtSubject, mode: "insensitive" } },
                            { code: { equals: restriction.taughtSubject, mode: "insensitive" } },
                        ],
                    },
                }
                : {}),
        };

        const scores = await prisma.score.findMany({
            where,
            include: {
                class: {
                    select: {
                        id: true,
                        name: true,
                        grade: true,
                    },
                },
                subject: {
                    select: {
                        id: true,
                        name: true,
                        code: true,
                    },
                },
            },
            orderBy: { createdAt: "desc" },
            take: 200,
        });

        res.json(scores);
    } catch (error) {
        console.error("Failed to get scores:", error);
        res.status(500).json({ error: "Failed to get scores" });
    }
});

// POST /api/staff/scores - Enter/create score
app.post("/api/staff/scores", async (req: RequestWithUser, res) => {
    const context = authorize(req, res, "students:read");
    if (!context) return;
    if (context.role === "VIEWER") {
        return res.status(403).json({ error: "Forbidden: insufficient role permissions" });
    }

    try {
        const { studentId, classId, subjectId, classScore, midTermScore, examScore, score, maxScore, term, academicYear, remarks } = req.body;

        const hasBreakdown = classScore !== undefined || midTermScore !== undefined || examScore !== undefined;
        const computedScore = hasBreakdown
            ? (Number(classScore ?? 0) + Number(midTermScore ?? 0) + Number(examScore ?? 0))
            : (score !== undefined ? Number(score) : undefined);

        if (!studentId || !classId || !subjectId || computedScore === undefined || !term || !academicYear) {
            return res.status(400).json({ error: "Missing required fields" });
        }

        const restriction = await getTeacherRestriction(req, context.schoolId);
        if (restriction && !restriction.allowedClassIds.includes(String(classId))) {
            return res.status(403).json({ error: "Forbidden: class not assigned to this teacher" });
        }

        const studentRecord = await prisma.student.findFirst({
            where: {
                id: String(studentId),
                schoolId: context.schoolId ?? "",
                classId: String(classId),
            },
            select: { id: true },
        });

        if (!studentRecord) {
            return res.status(400).json({ error: "Student is not enrolled in the selected class" });
        }

        const classSubject = await prisma.classSubject.findFirst({
            where: {
                classId: String(classId),
                subjectId: String(subjectId),
                class: { schoolId: context.schoolId ?? "" },
            },
            include: {
                subject: {
                    select: {
                        name: true,
                        code: true,
                    },
                },
            },
        });

        if (!classSubject) {
            return res.status(400).json({ error: "Subject is not assigned to the selected class" });
        }

        if (restriction) {
            const classIdValue = String(classId);
            const subjectIdValue = String(subjectId);
            const hasExplicitAssignments = restriction.teachingAssignments.length > 0;
            const allowedByExplicitAssignment = hasExplicitTeachingAssignment(
                restriction.teachingAssignments,
                classIdValue,
                subjectIdValue,
            );
            const allowedByLegacySubject =
                restriction.allowedClassIds.includes(classIdValue) &&
                hasTeacherSubjectAccess(restriction.taughtSubject, classSubject.subject);

            if (hasExplicitAssignments ? !allowedByExplicitAssignment : !allowedByLegacySubject) {
                return res.status(403).json({ error: "Forbidden: subject not assigned to this teacher" });
            }
        }

        const created = await prisma.score.create({
            data: {
                studentId: String(studentId),
                classId: String(classId),
                subjectId: String(subjectId),
                schoolId: context.schoolId ?? "",
                classScore: classScore !== undefined ? Number(classScore) : undefined,
                midTermScore: midTermScore !== undefined ? Number(midTermScore) : undefined,
                examScore: examScore !== undefined ? Number(examScore) : undefined,
                score: computedScore,
                maxScore: maxScore ? Number(maxScore) : 100,
                term: String(term),
                academicYear: String(academicYear),
                remarks: remarks ? String(remarks) : undefined,
            },
        });

        await logAudit({
            req,
            action: "SCORE_CREATE",
            entityType: "Score",
            entityId: created.id,
            schoolId: context.schoolId,
            actorUserId: context.userId,
            actorRole: context.role,
            status: "SUCCESS",
            metadata: { studentId: String(studentId), classId: String(classId), subjectId: String(subjectId), score },
        });

        res.status(201).json(created);
    } catch (error) {
        console.error("Failed to create score:", error);
        res.status(500).json({ error: "Failed to create score" });
    }
});

// PATCH /api/staff/scores/:id - Update score
app.patch("/api/staff/scores/:id", async (req: RequestWithUser, res) => {
    const context = authorize(req, res, "students:read");
    if (!context) return;
    if (context.role === "VIEWER") {
        return res.status(403).json({ error: "Forbidden: insufficient role permissions" });
    }

    try {
        const id = String(req.params.id);
        const { score, maxScore, remarks } = req.body;

        const existing = await prisma.score.findUnique({
            where: { id },
            include: {
                subject: {
                    select: {
                        name: true,
                        code: true,
                    },
                },
            },
        });

        if (!existing || existing.schoolId !== (context.schoolId ?? "")) {
            return res.status(404).json({ error: "Score not found" });
        }

        const restriction = await getTeacherRestriction(req, context.schoolId);
        if (restriction && !restriction.allowedClassIds.includes(existing.classId)) {
            return res.status(403).json({ error: "Forbidden: class not assigned to this teacher" });
        }

        if (restriction && !hasTeacherSubjectAccess(restriction.taughtSubject, existing.subject)) {
            return res.status(403).json({ error: "Forbidden: subject not assigned to this teacher" });
        }

        const updated = await prisma.score.update({
            where: { id: String(id) },
            data: {
                ...(score !== undefined ? { score: Number(score) } : {}),
                ...(maxScore !== undefined ? { maxScore: Number(maxScore) } : {}),
                ...(remarks !== undefined ? { remarks } : {}),
            },
        });

        await logAudit({
            req,
            action: "SCORE_UPDATE",
            entityType: "Score",
            entityId: id,
            schoolId: context.schoolId,
            actorUserId: context.userId,
            actorRole: context.role,
            status: "SUCCESS",
            metadata: { score: score !== undefined ? Number(score) : undefined, maxScore: maxScore !== undefined ? Number(maxScore) : undefined, remarks: remarks ? String(remarks) : undefined },
        });

        res.json(updated);
    } catch (error) {
        console.error("Failed to update score:", error);
        res.status(500).json({ error: "Failed to update score" });
    }
});

// GET /api/staff/assignments - Get assignments for classes
app.get("/api/staff/assignments", async (req: RequestWithUser, res) => {
    const context = authorize(req, res, "students:read");
    if (!context) return;

    try {
        const classId = typeof req.query.classId === "string" ? req.query.classId : undefined;

        const where: Prisma.AssignmentWhereInput = {
            schoolId: context.schoolId ?? "",
            ...(classId ? { classId } : {}),
        };

        const assignments = await prisma.assignment.findMany({
            where,
            include: {
                class: {
                    select: {
                        id: true,
                        name: true,
                        grade: true,
                    },
                },
                submissions: {
                    select: {
                        id: true,
                        studentId: true,
                        submittedAt: true,
                        grade: true,
                    },
                },
            },
            orderBy: { dueDate: "desc" },
            take: 100,
        });

        res.json(assignments);
    } catch (error) {
        console.error("Failed to get assignments:", error);
        res.status(500).json({ error: "Failed to get assignments" });
    }
});

// POST /api/staff/assignments - Create assignment
app.post("/api/staff/assignments", async (req: RequestWithUser, res) => {
    const context = authorize(req, res, "students:read");
    if (!context) return;
    if (context.role === "VIEWER") {
        return res.status(403).json({ error: "Forbidden: insufficient role permissions" });
    }

    try {
        const { title, description, classId, dueDate, filePath } = req.body;

        if (!title || !classId || !dueDate) {
            return res.status(400).json({ error: "Missing required fields" });
        }

        const created = await prisma.assignment.create({
            data: {
                title: String(title),
                description: description ? String(description) : undefined,
                classId: String(classId),
                schoolId: context.schoolId ?? "",
                dueDate: new Date(dueDate),
                filePath: filePath ? String(filePath) : undefined,
            },
        });

        await logAudit({
            req,
            action: "ASSIGNMENT_CREATE",
            entityType: "Assignment",
            entityId: created.id,
            schoolId: context.schoolId,
            actorUserId: context.userId,
            actorRole: context.role,
            status: "SUCCESS",
            metadata: { title: String(title), classId: String(classId) },
        });

        res.status(201).json(created);
    } catch (error) {
        console.error("Failed to create assignment:", error);
        res.status(500).json({ error: "Failed to create assignment" });
    }
});

// DELETE /api/staff/assignments/:id - Delete assignment
app.delete("/api/staff/assignments/:id", async (req: RequestWithUser, res) => {
    const context = authorize(req, res, "students:read");
    if (!context) return;
    if (context.role === "VIEWER") {
        return res.status(403).json({ error: "Forbidden: insufficient role permissions" });
    }

    try {
        const id = String(req.params.id);

        await prisma.assignment.delete({
            where: { id: String(id) },
        });

        await logAudit({
            req,
            action: "ASSIGNMENT_DELETE",
            entityType: "Assignment",
            entityId: id,
            schoolId: context.schoolId,
            actorUserId: context.userId,
            actorRole: context.role,
            status: "SUCCESS",
        });

        res.status(204).send();
    } catch (error) {
        console.error("Failed to delete assignment:", error);
        res.status(500).json({ error: "Failed to delete assignment" });
    }
});

// GET /api/staff/timetable - Get timetable for classes
app.get("/api/staff/timetable", async (req: RequestWithUser, res) => {
    const context = authorize(req, res, "students:read");
    if (!context) return;

    try {
        const classId = typeof req.query.classId === "string" ? req.query.classId : undefined;

        const where: Prisma.TimetableWhereInput = {
            schoolId: context.schoolId ?? "",
            ...(classId ? { classId } : {}),
        };

        const timetable = await prisma.timetable.findMany({
            where,
            include: {
                class: {
                    select: {
                        id: true,
                        name: true,
                        grade: true,
                    },
                },
            },
            orderBy: [{ dayOfWeek: "asc" }, { startTime: "asc" }],
        });

        res.json(timetable);
    } catch (error) {
        console.error("Failed to get timetable:", error);
        res.status(500).json({ error: "Failed to get timetable" });
    }
});

app.patch("/api/staff/classes/:id/leaders", async (req: RequestWithUser, res) => {
    const context = authorize(req, res, "students:read");
    if (!context) return;
    if (context.role === "VIEWER") {
        res.status(403).json({ error: "Forbidden: insufficient role permissions" });
        return;
    }

    const classId = String(req.params.id);
    const existingClass = await prisma.class.findUnique({
        where: { id: classId },
        select: {
            id: true,
            schoolId: true,
            teacherId: true,
            prefectStudentId: true,
            assistantPrefectStudentId: true,
        },
    });

    if (!existingClass) {
        res.status(404).json({ error: "Class not found" });
        return;
    }

    if (context.schoolId && existingClass.schoolId !== context.schoolId) {
        res.status(403).json({ error: "Forbidden" });
        return;
    }

    const teacherRestriction = await getTeacherRestriction(req, context.schoolId);
    if (teacherRestriction && existingClass.teacherId !== teacherRestriction.teacherId) {
        res.status(403).json({ error: "Only the class teacher can assign class leaders" });
        return;
    }

    const prefectStudentId = req.body.prefectStudentId === undefined
        ? existingClass.prefectStudentId
        : req.body.prefectStudentId || null;
    const assistantPrefectStudentId = req.body.assistantPrefectStudentId === undefined
        ? existingClass.assistantPrefectStudentId
        : req.body.assistantPrefectStudentId || null;

    if (prefectStudentId && assistantPrefectStudentId && prefectStudentId === assistantPrefectStudentId) {
        res.status(400).json({ error: "Prefect and assistant prefect must be different students" });
        return;
    }

    const selectedStudentIds = [prefectStudentId, assistantPrefectStudentId].filter(Boolean) as string[];
    if (selectedStudentIds.length > 0) {
        const studentsInClass = await prisma.student.findMany({
            where: {
                id: { in: selectedStudentIds },
                classId,
                schoolId: existingClass.schoolId,
            },
            select: { id: true },
        });

        if (studentsInClass.length !== selectedStudentIds.length) {
            res.status(400).json({ error: "Selected class leaders must belong to this class" });
            return;
        }
    }

    const updatedClass = await prisma.class.update({
        where: { id: classId },
        data: {
            prefectStudentId,
            assistantPrefectStudentId,
        },
        include: {
            prefectStudent: {
                select: {
                    id: true,
                    firstName: true,
                    otherNames: true,
                    lastName: true,
                },
            },
            assistantPrefectStudent: {
                select: {
                    id: true,
                    firstName: true,
                    otherNames: true,
                    lastName: true,
                },
            },
        },
    });

    await logAudit({
        req,
        action: "CLASS_LEADERSHIP_UPDATE",
        entityType: "Class",
        entityId: classId,
        schoolId: context.schoolId,
        actorUserId: context.userId,
        actorRole: context.role,
        metadata: {
            prefectStudentId,
            assistantPrefectStudentId,
        },
    });

    res.json(updatedClass);
});

// ============================================================================
// STUDENT EDIT / DEACTIVATE / IMPORT
// ============================================================================

app.patch("/api/admin/students/:id", async (req, res) => {
    const context = authorize(req, res, "students:write");
    if (!context) return;

    const studentId = req.params.id;
    const existing = await prisma.student.findUnique({ where: { id: studentId } });
    if (!existing) { res.status(404).json({ error: "Student not found" }); return; }
    if (context.schoolId && existing.schoolId !== context.schoolId) { res.status(403).json({ error: "Forbidden" }); return; }

    const updated = await prisma.student.update({
        where: { id: studentId },
        data: {
            ...(req.body.firstName ? { firstName: String(req.body.firstName) } : {}),
            ...(req.body.otherNames !== undefined ? { otherNames: req.body.otherNames || null } : {}),
            ...(req.body.lastName ? { lastName: String(req.body.lastName) } : {}),
            ...(req.body.gender !== undefined
                ? {
                    gender:
                        req.body.gender === "MALE" || req.body.gender === "FEMALE"
                            ? req.body.gender
                            : null,
                }
                : {}),
            ...(req.body.email !== undefined ? { email: req.body.email || null } : {}),
            ...(req.body.dateOfBirth ? { dateOfBirth: new Date(req.body.dateOfBirth) } : {}),
            ...(req.body.previousSchool !== undefined ? { previousSchool: req.body.previousSchool || null } : {}),
            ...(req.body.picture !== undefined ? { picture: req.body.picture || null } : {}),
            ...(req.body.medicalCondition !== undefined ? { medicalCondition: req.body.medicalCondition || null } : {}),
            ...(req.body.allergies !== undefined ? { allergies: req.body.allergies || null } : {}),
            ...(req.body.guardianInfo !== undefined ? { guardianInfo: req.body.guardianInfo || null } : {}),
            ...(req.body.classId !== undefined ? { classId: req.body.classId || null } : {}),
        },
    });

    await logAudit({ req, action: "STUDENT_UPDATE", entityType: "Student", entityId: studentId, schoolId: context.schoolId, actorUserId: context.userId, actorRole: context.role, metadata: req.body });
    res.json(updated);
});

app.patch("/api/admin/students/:id/deactivate", async (req, res) => {
    const context = authorize(req, res, "students:write");
    if (!context) return;

    const studentId = req.params.id;
    const existing = await prisma.student.findUnique({ where: { id: studentId } });
    if (!existing) { res.status(404).json({ error: "Student not found" }); return; }
    if (context.schoolId && existing.schoolId !== context.schoolId) { res.status(403).json({ error: "Forbidden" }); return; }

    const updated = await prisma.student.update({ where: { id: studentId }, data: { status: "INACTIVE" } });
    await logAudit({ req, action: "STUDENT_DEACTIVATE", entityType: "Student", entityId: studentId, schoolId: context.schoolId, actorUserId: context.userId, actorRole: context.role });
    res.json(updated);
});

app.patch("/api/admin/students/:id/activate", async (req, res) => {
    const context = authorize(req, res, "students:write");
    if (!context) return;

    const studentId = req.params.id;
    const existing = await prisma.student.findUnique({ where: { id: studentId } });
    if (!existing) { res.status(404).json({ error: "Student not found" }); return; }
    if (context.schoolId && existing.schoolId !== context.schoolId) { res.status(403).json({ error: "Forbidden" }); return; }

    const updated = await prisma.student.update({ where: { id: studentId }, data: { status: "ACTIVE" } });
    await logAudit({ req, action: "STUDENT_ACTIVATE", entityType: "Student", entityId: studentId, schoolId: context.schoolId, actorUserId: context.userId, actorRole: context.role });
    res.json(updated);
});

app.post("/api/admin/students/import", async (req, res) => {
    const context = authorize(req, res, "students:write");
    if (!context) return;

    const schoolId = context.schoolId ?? req.body.schoolId;
    if (!schoolId) { res.status(400).json({ error: "Missing school scope" }); return; }

    const rows: Array<{
        firstName: string;
        otherNames?: string;
        lastName: string;
        gender?: "MALE" | "FEMALE";
        email?: string;
        dateOfBirth?: string;
        previousSchool?: string;
        medicalCondition?: string;
        allergies?: string;
        picture?: string;
        fatherFirstName?: string;
        fatherLastName?: string;
        fatherPhone?: string;
        fatherEmail?: string;
        fatherOccupation?: string;
        fatherResidentialAddress?: string;
        fatherPostalAddress?: string;
        motherFirstName?: string;
        motherLastName?: string;
        motherPhone?: string;
        motherEmail?: string;
        motherOccupation?: string;
        motherResidentialAddress?: string;
        motherPostalAddress?: string;
        classId?: string;
    }> = req.body.rows ?? [];
    if (!Array.isArray(rows) || rows.length === 0) { res.status(400).json({ error: "No rows provided" }); return; }

    const created = await prisma.$transaction(
        rows.filter(r => r.firstName && r.lastName).map(r =>
            prisma.student.create({
                data: {
                    firstName: r.firstName,
                    otherNames: r.otherNames || null,
                    lastName: r.lastName,
                    gender: r.gender === "MALE" || r.gender === "FEMALE" ? r.gender : null,
                    email: r.email || null,
                    dateOfBirth: r.dateOfBirth ? new Date(r.dateOfBirth) : new Date("2000-01-01"),
                    previousSchool: r.previousSchool || null,
                    picture: r.picture || null,
                    medicalCondition: r.medicalCondition || null,
                    allergies: r.allergies || null,
                    guardianInfo: {
                        father: {
                            firstName: r.fatherFirstName,
                            lastName: r.fatherLastName,
                            phone: r.fatherPhone,
                            email: r.fatherEmail,
                            occupation: r.fatherOccupation,
                            residentialAddress: r.fatherResidentialAddress,
                            postalAddress: r.fatherPostalAddress,
                        },
                        mother: {
                            firstName: r.motherFirstName,
                            lastName: r.motherLastName,
                            phone: r.motherPhone,
                            email: r.motherEmail,
                            occupation: r.motherOccupation,
                            residentialAddress: r.motherResidentialAddress,
                            postalAddress: r.motherPostalAddress,
                        },
                    },
                    schoolId,
                    classId: r.classId || null,
                },
            })
        )
    );

    await logAudit({ req, action: "STUDENT_IMPORT", entityType: "Student", schoolId, actorUserId: context.userId, actorRole: context.role, metadata: { count: created.length } });
    res.status(201).json({ imported: created.length, students: created });
});

// ============================================================================
// TEACHER EDIT / DEACTIVATE / IMPORT
// ============================================================================

app.patch("/api/admin/teachers/:id", async (req, res) => {
    const context = authorize(req, res, "teachers:write");
    if (!context) return;

    const teacherId = req.params.id;
    const existing = await prisma.teacher.findUnique({ where: { id: teacherId } });
    if (!existing) { res.status(404).json({ error: "Teacher not found" }); return; }
    if (context.schoolId && existing.schoolId !== context.schoolId) { res.status(403).json({ error: "Forbidden" }); return; }

    const updated = await prisma.teacher.update({
        where: { id: teacherId },
        data: {
            ...(req.body.firstName ? { firstName: String(req.body.firstName) } : {}),
            ...(req.body.lastName ? { lastName: String(req.body.lastName) } : {}),
            ...(req.body.otherNames !== undefined ? { otherNames: req.body.otherNames || null } : {}),
            ...(req.body.dateOfBirth !== undefined ? { dateOfBirth: req.body.dateOfBirth ? new Date(String(req.body.dateOfBirth)) : null } : {}),
            ...(req.body.ssnitNumber !== undefined ? { ssnitNumber: req.body.ssnitNumber || null } : {}),
            ...(req.body.educationalLevel !== undefined ? { educationalLevel: req.body.educationalLevel || null } : {}),
            ...(req.body.certifications !== undefined ? { certifications: req.body.certifications || null } : {}),
            ...(req.body.picture !== undefined ? { picture: req.body.picture || null } : {}),
            ...(req.body.maritalStatus !== undefined ? { maritalStatus: req.body.maritalStatus || null } : {}),
            ...(req.body.nextOfKin !== undefined ? { nextOfKin: req.body.nextOfKin || null } : {}),
            ...(req.body.nextOfKinRelationship !== undefined ? { nextOfKinRelationship: req.body.nextOfKinRelationship || null } : {}),
            ...(req.body.residentialAddress !== undefined ? { residentialAddress: req.body.residentialAddress || null } : {}),
            ...(req.body.email ? { email: String(req.body.email) } : {}),
            ...(req.body.phone !== undefined ? { phone: req.body.phone || null } : {}),
            ...(req.body.subject !== undefined ? { subject: req.body.subject || null } : {}),
        },
    });

    await logAudit({ req, action: "TEACHER_UPDATE", entityType: "Teacher", entityId: teacherId, schoolId: context.schoolId, actorUserId: context.userId, actorRole: context.role, metadata: req.body });
    res.json(updated);
});

app.patch("/api/admin/teachers/:id/deactivate", async (req, res) => {
    const context = authorize(req, res, "teachers:write");
    if (!context) return;

    const teacherId = req.params.id;
    const existing = await prisma.teacher.findUnique({ where: { id: teacherId } });
    if (!existing) { res.status(404).json({ error: "Teacher not found" }); return; }
    if (context.schoolId && existing.schoolId !== context.schoolId) { res.status(403).json({ error: "Forbidden" }); return; }

    const updated = await prisma.teacher.update({ where: { id: teacherId }, data: { status: "INACTIVE" } });
    await logAudit({ req, action: "TEACHER_DEACTIVATE", entityType: "Teacher", entityId: teacherId, schoolId: context.schoolId, actorUserId: context.userId, actorRole: context.role });
    res.json(updated);
});

app.patch("/api/admin/teachers/:id/activate", async (req, res) => {
    const context = authorize(req, res, "teachers:write");
    if (!context) return;

    const teacherId = req.params.id;
    const existing = await prisma.teacher.findUnique({ where: { id: teacherId } });
    if (!existing) { res.status(404).json({ error: "Teacher not found" }); return; }
    if (context.schoolId && existing.schoolId !== context.schoolId) { res.status(403).json({ error: "Forbidden" }); return; }

    const updated = await prisma.teacher.update({ where: { id: teacherId }, data: { status: "ACTIVE" } });
    await logAudit({ req, action: "TEACHER_ACTIVATE", entityType: "Teacher", entityId: teacherId, schoolId: context.schoolId, actorUserId: context.userId, actorRole: context.role });
    res.json(updated);
});

app.post("/api/admin/teachers/import", async (req, res) => {
    const context = authorize(req, res, "teachers:write");
    if (!context) return;

    const schoolId = context.schoolId ?? req.body.schoolId;
    if (!schoolId) { res.status(400).json({ error: "Missing school scope" }); return; }

    const rows: Array<{
        firstName?: string;
        lastName?: string;
        otherNames?: string;
        dateOfBirth?: string;
        ssnitNumber?: string;
        educationalLevel?: string;
        certifications?: string;
        picture?: string;
        maritalStatus?: string;
        nextOfKin?: string;
        nextOfKinRelationship?: string;
        residentialAddress?: string;
        email?: string;
        phone?: string;
        subject?: string;
    }> = req.body.rows ?? [];
    if (!Array.isArray(rows) || rows.length === 0) { res.status(400).json({ error: "No rows provided" }); return; }

    const defaultTeacherPasswordHash = await bcrypt.hash(process.env.DEFAULT_TEACHER_PASSWORD ?? "Teacher@123", 10);

    const created: Awaited<ReturnType<typeof prisma.teacher.create>>[] = [];
    const errors: { row: number; error: string }[] = [];

    for (let i = 0; i < rows.length; i++) {
        const r = rows[i]!;
        const validation = createTeacherSchema.safeParse({
            firstName: r.firstName ?? "",
            lastName: r.lastName ?? "",
            otherNames: r.otherNames ?? "",
            dateOfBirth: r.dateOfBirth ?? "",
            ssnitNumber: r.ssnitNumber ?? "",
            educationalLevel: r.educationalLevel ?? "",
            certifications: r.certifications ?? "",
            picture: r.picture ?? "",
            maritalStatus: r.maritalStatus ?? "",
            nextOfKin: r.nextOfKin ?? "",
            nextOfKinRelationship: r.nextOfKinRelationship ?? "",
            residentialAddress: r.residentialAddress ?? "",
            email: r.email ?? "",
            phone: r.phone ?? "",
            subject: r.subject ?? "",
            schoolId,
        });

        if (!validation.success) {
            errors.push({
                row: i + 2,
                error: validation.error.issues.map((issue) => issue.message).join("; "),
            });
            continue;
        }

        try {
            const t = await prisma.teacher.create({
                data: {
                    firstName: validation.data.firstName,
                    lastName: validation.data.lastName,
                    otherNames: validation.data.otherNames || null,
                    dateOfBirth: new Date(validation.data.dateOfBirth),
                    ssnitNumber: validation.data.ssnitNumber,
                    educationalLevel: validation.data.educationalLevel,
                    certifications: validation.data.certifications || null,
                    picture: validation.data.picture || null,
                    maritalStatus: validation.data.maritalStatus,
                    nextOfKin: validation.data.nextOfKin,
                    nextOfKinRelationship: validation.data.nextOfKinRelationship,
                    residentialAddress: validation.data.residentialAddress,
                    email: validation.data.email,
                    passwordHash: defaultTeacherPasswordHash,
                    phone: validation.data.phone,
                    subject: validation.data.subject || null,
                    schoolId,
                },
            });
            created.push(t);
        } catch {
            errors.push({ row: i + 2, error: `Duplicate email: ${validation.data.email}` });
        }
    }

    await logAudit({ req, action: "TEACHER_IMPORT", entityType: "Teacher", schoolId, actorUserId: context.userId, actorRole: context.role, metadata: { count: created.length, errors: errors.length } });
    res.status(201).json({ imported: created.length, teachers: created, errors });
});

// ============================================================================
// CLASS EDIT
// ============================================================================

app.patch("/api/admin/classes/:id", async (req, res) => {
    const context = authorize(req, res, "classes:write");
    if (!context) return;

    const classId = req.params.id;
    const existing = await prisma.class.findUnique({ where: { id: classId } });
    if (!existing) { res.status(404).json({ error: "Class not found" }); return; }
    if (context.schoolId && existing.schoolId !== context.schoolId) { res.status(403).json({ error: "Forbidden" }); return; }

    const nextTeacherId = req.body.teacherId !== undefined ? (req.body.teacherId || null) : existing.teacherId;
    const nextAssistantTeacherId = req.body.assistantTeacherId !== undefined ? (req.body.assistantTeacherId || null) : existing.assistantTeacherId;

    const teacherAssignmentValidation = await validateClassTeacherAssignments({
        schoolId: existing.schoolId,
        classIdToExclude: classId,
        teacherId: nextTeacherId,
        assistantTeacherId: nextAssistantTeacherId,
    });
    if (!teacherAssignmentValidation.ok) {
        res.status(400).json({ error: teacherAssignmentValidation.error });
        return;
    }

    const updated = await prisma.class.update({
        where: { id: classId },
        data: {
            ...(req.body.name ? { name: String(req.body.name) } : {}),
            ...(req.body.grade ? { grade: String(req.body.grade) } : {}),
            ...(req.body.section !== undefined ? { section: req.body.section || null } : {}),
            ...(req.body.academicYear ? { academicYear: String(req.body.academicYear) } : {}),
            ...(req.body.feeAmount !== undefined ? { feeAmount: req.body.feeAmount === null || req.body.feeAmount === "" ? null : Number(req.body.feeAmount) } : {}),
            ...(req.body.teacherId !== undefined ? { teacherId: req.body.teacherId || null } : {}),
            ...(req.body.assistantTeacherId !== undefined ? { assistantTeacherId: req.body.assistantTeacherId || null } : {}),
            ...(req.body.prefectStudentId !== undefined ? { prefectStudentId: req.body.prefectStudentId || null } : {}),
            ...(req.body.assistantPrefectStudentId !== undefined ? { assistantPrefectStudentId: req.body.assistantPrefectStudentId || null } : {}),
        },
    });

    await logAudit({ req, action: "CLASS_UPDATE", entityType: "Class", entityId: classId, schoolId: context.schoolId, actorUserId: context.userId, actorRole: context.role, metadata: req.body });
    res.json(updated);
});

// ============================================================================
// SUBJECT EDIT / DELETE
// ============================================================================

app.patch("/api/admin/subjects/:id", async (req, res) => {
    const context = authorize(req, res, "subjects:write");
    if (!context) return;

    const subjectId = req.params.id;
    const existing = await prisma.subject.findUnique({ where: { id: subjectId } });
    if (!existing) { res.status(404).json({ error: "Subject not found" }); return; }
    if (context.schoolId && existing.schoolId !== context.schoolId) { res.status(403).json({ error: "Forbidden" }); return; }

    const updated = await prisma.subject.update({
        where: { id: subjectId },
        data: {
            ...(req.body.name ? { name: String(req.body.name) } : {}),
            ...(req.body.code ? { code: String(req.body.code) } : {}),
            ...(req.body.groupName !== undefined ? { groupName: req.body.groupName || null } : {}),
            ...(req.body.description !== undefined ? { description: req.body.description || null } : {}),
        },
    });

    await logAudit({ req, action: "SUBJECT_UPDATE", entityType: "Subject", entityId: subjectId, schoolId: context.schoolId, actorUserId: context.userId, actorRole: context.role, metadata: req.body });
    res.json(updated);
});

app.delete("/api/admin/subjects/:id", async (req, res) => {
    const context = authorize(req, res, "subjects:write");
    if (!context) return;

    const subjectId = req.params.id;
    const existing = await prisma.subject.findUnique({ where: { id: subjectId } });
    if (!existing) { res.status(404).json({ error: "Subject not found" }); return; }
    if (context.schoolId && existing.schoolId !== context.schoolId) { res.status(403).json({ error: "Forbidden" }); return; }

    await prisma.subject.delete({ where: { id: subjectId } });
    await logAudit({ req, action: "SUBJECT_DELETE", entityType: "Subject", entityId: subjectId, schoolId: context.schoolId, actorUserId: context.userId, actorRole: context.role });
    res.json({ ok: true });
});

// ============================================================================
// SCHOOL SETTINGS (academic year, grading, fee categories)
// ============================================================================

app.get("/api/admin/settings", async (req, res) => {
    const context = authorize(req, res, "reports:read");
    if (!context) return;

    const schoolId = context.schoolId;
    if (!schoolId) { res.status(400).json({ error: "No school scope" }); return; }

    const settings = await prisma.schoolSettings.upsert({
        where: { schoolId },
        create: { schoolId, academicYear: "2025-2026" },
        update: {},
    });

    const school = await prisma.school.findUnique({
        where: { id: schoolId },
        select: { logo: true },
    });

    res.json({
        ...settings,
        logo: school?.logo ?? null,
    });
});

app.patch("/api/admin/settings", async (req, res) => {
    const context = authorize(req, res, "schools:write");
    if (!context) return;

    const schoolId = context.schoolId;
    if (!schoolId) { res.status(400).json({ error: "No school scope" }); return; }

    const updated = await prisma.schoolSettings.upsert({
        where: { schoolId },
        create: {
            schoolId,
            academicYear: req.body.academicYear ?? "2025-2026",
            gradingConfig: req.body.gradingConfig ?? null,
            feeCategories: req.body.feeCategories ?? null,
        },
        update: {
            ...(req.body.academicYear !== undefined ? { academicYear: String(req.body.academicYear) } : {}),
            ...(req.body.gradingConfig !== undefined ? { gradingConfig: req.body.gradingConfig } : {}),
            ...(req.body.feeCategories !== undefined ? { feeCategories: req.body.feeCategories } : {}),
        },
    });

    if (req.body.logo !== undefined) {
        await prisma.school.update({
            where: { id: schoolId },
            data: {
                logo: req.body.logo ? String(req.body.logo) : null,
            },
        });
    }

    const school = await prisma.school.findUnique({
        where: { id: schoolId },
        select: { logo: true },
    });

    await logAudit({ req, action: "SETTINGS_UPDATE", entityType: "SchoolSettings", entityId: updated.id, schoolId, actorUserId: context.userId, actorRole: context.role, metadata: { academicYear: updated.academicYear } });
    res.json({
        ...updated,
        logo: school?.logo ?? null,
    });
});

// Global error handler
app.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
    const bodyParserError = err as Error & { type?: string; limit?: number; length?: number };
    if (bodyParserError.type === "entity.too.large") {
        res.status(413).json({
            error: "Request payload too large",
            details: `Payload exceeds API limit (${apiBodyLimit}).`,
        });
        return;
    }

    console.error("Unhandled error:", err);
    res.status(500).json({ error: "Internal server error" });
});

app.listen(port, () => {
    console.log(`Backend running on http://localhost:${port}`);
});
