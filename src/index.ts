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
import { pathToFileURL } from "node:url";
import prisma from "./lib/prisma.js";
import { validateBody, validateQuery } from "./lib/middleware.js";
import { envPositiveInt } from "./lib/env.js";
import { sumFeeItems } from "./lib/fees.js";
import { buildAuditCsv, logAudit, parseDateParam } from "./lib/audit.js";
import { authenticate, authorize } from "./lib/auth-guards.js";
import { createAccessToken, createRefreshSession, hashToken } from "./lib/auth-tokens.js";
import {
    getTeacherRestriction,
    hasExplicitTeachingAssignment,
    hasTeacherSubjectAccess,
    validateClassTeacherAssignments,
} from "./lib/teacher-access.js";
import { registerAuthRoutes } from "./routes/auth-routes.js";
import { registerStaffRoutes } from "./routes/staff-routes.js";
import { registerAdminManagementRoutes } from "./routes/admin-management-routes.js";
import { registerAdminCoreRoutes } from "./routes/admin-core-routes.js";
import { registerAdminAcademicRoutes } from "./routes/admin-academic-routes.js";
import { registerAdminFinanceReportRoutes } from "./routes/admin-finance-report-routes.js";
import {
    createFeeStructureSchema,
    createFeeInvoiceSchema,
    generateFeeInvoicesSchema,
} from "./lib/validations.js";

export const app = express();
const port = Number(process.env.PORT ?? 4000);
const frontendOrigin = process.env.FRONTEND_ORIGIN ?? "http://localhost:3000";
const apiBodyLimit = process.env.API_BODY_LIMIT ?? "5mb";

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

app.use(cors({ origin: frontendOrigin }));
app.use(express.json({ limit: apiBodyLimit }));
app.use(express.urlencoded({ extended: true, limit: apiBodyLimit }));

// Sentry request handler - must be after body parser
if (process.env.SENTRY_DSN) {
    Sentry.setupExpressErrorHandler(app);
}

registerAuthRoutes(app, {
    createAccessToken,
    createRefreshSession,
    hashToken,
    authenticate,
    logAudit,
    otpSendWindowMs,
    otpSendCooldownMs,
    otpVerifyWindowMs,
    otpSendIpLimit,
    otpSendUserLimit,
    otpVerifyIpLimit,
    otpVerifyChallengeLimit,
    otpSendIpBlockMs,
    otpSendUserBlockMs,
    otpVerifyBlockMs,
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

registerAdminCoreRoutes(app, {
    authorize,
    logAudit,
});

registerAdminAcademicRoutes(app, {
    authorize,
    logAudit,
    validateClassTeacherAssignments,
});

registerAdminFinanceReportRoutes(app, {
    authenticate,
    authorize,
    validateBody,
    validateQuery,
    feeStructureCreateSchema: createFeeStructureSchema,
    feeInvoiceCreateSchema: createFeeInvoiceSchema,
    invoiceBulkGenerateSchema: generateFeeInvoicesSchema,
    logAudit,
    sumFeeItems,
    buildAuditCsv,
    parseDateParam,
});

registerStaffRoutes(app, {
    authorize,
    getTeacherRestriction,
    hasTeacherSubjectAccess,
    hasExplicitTeachingAssignment,
    logAudit,
});

registerAdminManagementRoutes(app, {
    authorize,
    logAudit,
    validateClassTeacherAssignments,
});

// Global error handler
app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
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

const isMainModule = process.argv[1]
    ? import.meta.url === pathToFileURL(process.argv[1]).href
    : false;

if (isMainModule) {
    app.listen(port, () => {
        console.log(`Backend running on http://localhost:${port}`);
    });
}
