import assert from "node:assert/strict";
import crypto from "node:crypto";
import test, { after } from "node:test";
import bcrypt from "bcryptjs";
import request from "supertest";

import { app } from "../../src/index.js";
import { shutdownOtpSecurity } from "../../src/lib/otp-security.js";
import prisma from "../../src/lib/prisma.js";
import { createAccessToken, stubPrismaMethod } from "./test-helpers.js";

after(async () => {
    await shutdownOtpSecurity();
});


test("GET /api/health returns service health payload", async () => {
    const response = await request(app)
        .get("/api/health")
        .expect(200);

    assert.equal(response.body.ok, true);
    assert.equal(response.body.service, "school-saas-backend");
    assert.equal(response.body.database, "connected");
});



test("POST /api/auth/login rejects malformed payload with 400", async () => {
    const response = await request(app)
        .post("/api/auth/login")
        .send({ email: "not-an-email" })
        .expect(400);

    assert.equal(response.body.error, "Validation failed");
    assert.ok(Array.isArray(response.body.details));

    const fields = response.body.details.map((item: { field: string }) => item.field);
    assert.ok(fields.includes("email"));
    assert.ok(fields.includes("password"));
});



test("POST /api/auth/refresh rejects empty payload with 400", async () => {
    const response = await request(app)
        .post("/api/auth/refresh")
        .send({})
        .expect(400);

    assert.equal(response.body.error, "Validation failed");
    assert.ok(Array.isArray(response.body.details));
    assert.ok(response.body.details.some((item: { field: string }) => item.field === "refreshToken"));
});



test("POST /api/auth/login succeeds for admin user without OTP", async () => {
    const password = "Admin@123";
    const passwordHash = await bcrypt.hash(password, 10);

    const restoreAdminUserFindUnique = stubPrismaMethod(
        prisma.adminUser,
        "findUnique",
        (async (args: unknown) => {
            const where = (args as { where?: { email?: string; id?: string } })?.where;
            if (where?.email === "admin@example.com") {
                return {
                    id: "admin_1",
                    name: "System Admin",
                    email: "admin@example.com",
                    role: "SUPER_ADMIN",
                    schoolId: null,
                    passwordHash,
                    phone: null,
                };
            }
            if (where?.id === "admin_1") {
                return { id: "admin_1" };
            }
            return null;
        }) as typeof prisma.adminUser.findUnique,
    );
    const restoreTeacherFindUnique = stubPrismaMethod(
        prisma.teacher,
        "findUnique",
        (async () => null) as typeof prisma.teacher.findUnique,
    );
    const restoreAuthSessionCreate = stubPrismaMethod(
        prisma.authSession,
        "create",
        (async () => ({ id: "session_1" })) as typeof prisma.authSession.create,
    );
    const restoreAuditLogCreate = stubPrismaMethod(
        prisma.auditLog,
        "create",
        (async () => ({ id: "audit_login_1" })) as typeof prisma.auditLog.create,
    );

    try {
        const response = await request(app)
            .post("/api/auth/login")
            .send({ email: "admin@example.com", password })
            .expect(200);

        assert.equal(typeof response.body.accessToken, "string");
        assert.ok(response.body.accessToken.length > 20);
        assert.equal(typeof response.body.refreshToken, "string");
        assert.ok(response.body.refreshToken.length > 20);
        assert.equal(response.body.user.email, "admin@example.com");
        assert.equal(response.body.user.role, "SUPER_ADMIN");
    } finally {
        restoreAdminUserFindUnique();
        restoreTeacherFindUnique();
        restoreAuthSessionCreate();
        restoreAuditLogCreate();
    }
});



test("POST /api/auth/refresh rotates refresh token for valid admin session", async () => {
    const providedRefreshToken = "refresh-token-old-1";
    const providedHash = crypto.createHash("sha256").update(providedRefreshToken).digest("hex");

    const restoreAuthSessionFindUnique = stubPrismaMethod(
        prisma.authSession,
        "findUnique",
        (async (args: unknown) => {
            const where = (args as { where?: { tokenHash?: string } })?.where;
            if (where?.tokenHash === providedHash) {
                return {
                    id: "session_old_1",
                    userId: "admin_1",
                    userType: "ADMIN_USER",
                    tokenHash: providedHash,
                    expiresAt: new Date(Date.now() + 60 * 60 * 1000),
                    revokedAt: null,
                };
            }
            return null;
        }) as typeof prisma.authSession.findUnique,
    );
    const restoreAuthSessionUpdate = stubPrismaMethod(
        prisma.authSession,
        "update",
        (async () => ({ id: "session_old_1" })) as typeof prisma.authSession.update,
    );
    const restoreAuthSessionCreate = stubPrismaMethod(
        prisma.authSession,
        "create",
        (async () => ({ id: "session_new_1" })) as typeof prisma.authSession.create,
    );
    const restoreAdminUserFindUnique = stubPrismaMethod(
        prisma.adminUser,
        "findUnique",
        (async (args: unknown) => {
            const where = (args as { where?: { id?: string } })?.where;
            if (where?.id === "admin_1") {
                return {
                    id: "admin_1",
                    name: "System Admin",
                    email: "admin@example.com",
                    role: "SUPER_ADMIN",
                    schoolId: null,
                    passwordHash: "hash",
                };
            }
            return null;
        }) as typeof prisma.adminUser.findUnique,
    );
    const restoreAuditLogCreate = stubPrismaMethod(
        prisma.auditLog,
        "create",
        (async () => ({ id: "audit_refresh_1" })) as typeof prisma.auditLog.create,
    );

    try {
        const response = await request(app)
            .post("/api/auth/refresh")
            .send({ refreshToken: providedRefreshToken })
            .expect(200);

        assert.equal(typeof response.body.accessToken, "string");
        assert.equal(typeof response.body.refreshToken, "string");
        assert.notEqual(response.body.refreshToken, providedRefreshToken);
    } finally {
        restoreAuthSessionFindUnique();
        restoreAuthSessionUpdate();
        restoreAuthSessionCreate();
        restoreAdminUserFindUnique();
        restoreAuditLogCreate();
    }
});



test("POST /api/auth/logout revokes provided refresh token for authenticated user", async () => {
    const restoreAuthSessionUpdateMany = stubPrismaMethod(
        prisma.authSession,
        "updateMany",
        (async () => ({ count: 1 })) as typeof prisma.authSession.updateMany,
    );
    const restoreAdminUserFindUnique = stubPrismaMethod(
        prisma.adminUser,
        "findUnique",
        (async () => ({ id: "admin_super_1" })) as typeof prisma.adminUser.findUnique,
    );
    const restoreAuditLogCreate = stubPrismaMethod(
        prisma.auditLog,
        "create",
        (async () => ({ id: "audit_logout_1" })) as typeof prisma.auditLog.create,
    );

    try {
        const token = createAccessToken({
            sub: "admin_super_1",
            role: "SUPER_ADMIN",
            schoolId: null,
            userType: "ADMIN_USER",
        });

        const response = await request(app)
            .post("/api/auth/logout")
            .set("authorization", `Bearer ${token}`)
            .send({ refreshToken: "some-refresh-token" })
            .expect(200);

        assert.equal(response.body.ok, true);
    } finally {
        restoreAuthSessionUpdateMany();
        restoreAdminUserFindUnique();
        restoreAuditLogCreate();
    }
});



test("POST /api/auth/refresh returns 401 for unknown refresh token", async () => {
    const restoreAuthSessionFindUnique = stubPrismaMethod(
        prisma.authSession,
        "findUnique",
        (async () => null) as typeof prisma.authSession.findUnique,
    );
    const restoreAuditLogCreate = stubPrismaMethod(
        prisma.auditLog,
        "create",
        (async () => ({ id: "audit_refresh_fail_1" })) as typeof prisma.auditLog.create,
    );

    try {
        const response = await request(app)
            .post("/api/auth/refresh")
            .send({ refreshToken: "invalid-refresh-token" })
            .expect(401);

        assert.equal(response.body.error, "Invalid refresh token");
    } finally {
        restoreAuthSessionFindUnique();
        restoreAuditLogCreate();
    }
});



test("POST /api/auth/logout returns 401 without bearer token", async () => {
    const response = await request(app)
        .post("/api/auth/logout")
        .send({ refreshToken: "any" })
        .expect(401);

    assert.equal(response.body.error, "Unauthorized: missing bearer token");
});



test("POST /api/auth/refresh returns 401 for revoked refresh session", async () => {
    const providedRefreshToken = "refresh-token-revoked";
    const providedHash = crypto.createHash("sha256").update(providedRefreshToken).digest("hex");

    const restoreAuthSessionFindUnique = stubPrismaMethod(
        prisma.authSession,
        "findUnique",
        (async () => ({
            id: "session_revoked_1",
            userId: "admin_1",
            userType: "ADMIN_USER",
            tokenHash: providedHash,
            expiresAt: new Date(Date.now() + 60 * 60 * 1000),
            revokedAt: new Date(),
        })) as typeof prisma.authSession.findUnique,
    );
    const restoreAuditLogCreate = stubPrismaMethod(
        prisma.auditLog,
        "create",
        (async () => ({ id: "audit_refresh_revoked" })) as typeof prisma.auditLog.create,
    );

    try {
        const response = await request(app)
            .post("/api/auth/refresh")
            .send({ refreshToken: providedRefreshToken })
            .expect(401);

        assert.equal(response.body.error, "Invalid refresh token");
    } finally {
        restoreAuthSessionFindUnique();
        restoreAuditLogCreate();
    }
});



test("POST /api/auth/refresh returns 401 for expired refresh session", async () => {
    const providedRefreshToken = "refresh-token-expired";
    const providedHash = crypto.createHash("sha256").update(providedRefreshToken).digest("hex");

    const restoreAuthSessionFindUnique = stubPrismaMethod(
        prisma.authSession,
        "findUnique",
        (async () => ({
            id: "session_expired_1",
            userId: "admin_1",
            userType: "ADMIN_USER",
            tokenHash: providedHash,
            expiresAt: new Date(Date.now() - 60 * 1000),
            revokedAt: null,
        })) as typeof prisma.authSession.findUnique,
    );
    const restoreAuditLogCreate = stubPrismaMethod(
        prisma.auditLog,
        "create",
        (async () => ({ id: "audit_refresh_expired" })) as typeof prisma.auditLog.create,
    );

    try {
        const response = await request(app)
            .post("/api/auth/refresh")
            .send({ refreshToken: providedRefreshToken })
            .expect(401);

        assert.equal(response.body.error, "Invalid refresh token");
    } finally {
        restoreAuthSessionFindUnique();
        restoreAuditLogCreate();
    }
});



test("POST /api/auth/refresh returns 401 when session admin user no longer exists", async () => {
    const providedRefreshToken = "refresh-token-missing-user";
    const providedHash = crypto.createHash("sha256").update(providedRefreshToken).digest("hex");

    const restoreAuthSessionFindUnique = stubPrismaMethod(
        prisma.authSession,
        "findUnique",
        (async () => ({
            id: "session_admin_missing_1",
            userId: "admin_missing_1",
            userType: "ADMIN_USER",
            tokenHash: providedHash,
            expiresAt: new Date(Date.now() + 60 * 60 * 1000),
            revokedAt: null,
        })) as typeof prisma.authSession.findUnique,
    );
    const restoreAuthSessionUpdate = stubPrismaMethod(
        prisma.authSession,
        "update",
        (async () => ({ id: "session_admin_missing_1" })) as typeof prisma.authSession.update,
    );
    const restoreAdminUserFindUnique = stubPrismaMethod(
        prisma.adminUser,
        "findUnique",
        (async () => null) as typeof prisma.adminUser.findUnique,
    );

    try {
        const response = await request(app)
            .post("/api/auth/refresh")
            .send({ refreshToken: providedRefreshToken })
            .expect(401);

        assert.equal(response.body.error, "Invalid refresh token");
    } finally {
        restoreAuthSessionFindUnique();
        restoreAuthSessionUpdate();
        restoreAdminUserFindUnique();
    }
});



test("POST /api/auth/logout without refresh token revokes all active sessions for user", async () => {
    let capturedUserId: string | undefined;
    let capturedUserType: string | undefined;

    const restoreAuthSessionUpdateMany = stubPrismaMethod(
        prisma.authSession,
        "updateMany",
        (async (args: unknown) => {
            const where = (args as { where?: { userId?: string; userType?: string } })?.where;
            capturedUserId = where?.userId;
            capturedUserType = where?.userType;
            return { count: 3 };
        }) as typeof prisma.authSession.updateMany,
    );
    const restoreAdminUserFindUnique = stubPrismaMethod(
        prisma.adminUser,
        "findUnique",
        (async () => ({ id: "admin_super_1" })) as typeof prisma.adminUser.findUnique,
    );
    const restoreAuditLogCreate = stubPrismaMethod(
        prisma.auditLog,
        "create",
        (async () => ({ id: "audit_logout_all_1" })) as typeof prisma.auditLog.create,
    );

    try {
        const token = createAccessToken({
            sub: "admin_super_1",
            role: "SUPER_ADMIN",
            schoolId: null,
            userType: "ADMIN_USER",
        });

        const response = await request(app)
            .post("/api/auth/logout")
            .set("authorization", `Bearer ${token}`)
            .send({})
            .expect(200);

        assert.equal(response.body.ok, true);
        assert.equal(capturedUserId, "admin_super_1");
        assert.equal(capturedUserType, "ADMIN_USER");
    } finally {
        restoreAuthSessionUpdateMany();
        restoreAdminUserFindUnique();
        restoreAuditLogCreate();
    }
});



test("POST /api/auth/refresh rotates refresh token for TEACHER session", async () => {
    const providedRefreshToken = "refresh-token-teacher-1";
    const providedHash = crypto.createHash("sha256").update(providedRefreshToken).digest("hex");

    const restoreAuthSessionFindUnique = stubPrismaMethod(
        prisma.authSession,
        "findUnique",
        (async () => ({
            id: "session_teacher_old_1",
            userId: "teacher_1",
            userType: "TEACHER",
            tokenHash: providedHash,
            expiresAt: new Date(Date.now() + 60 * 60 * 1000),
            revokedAt: null,
        })) as typeof prisma.authSession.findUnique,
    );
    const restoreAuthSessionUpdate = stubPrismaMethod(
        prisma.authSession,
        "update",
        (async () => ({ id: "session_teacher_old_1" })) as typeof prisma.authSession.update,
    );
    const restoreTeacherFindUnique = stubPrismaMethod(
        prisma.teacher,
        "findUnique",
        (async () => ({
            id: "teacher_1",
            schoolId: "school_1",
            firstName: "Kojo",
            lastName: "Owusu",
            email: "kojo@example.com",
            status: "ACTIVE",
        })) as typeof prisma.teacher.findUnique,
    );
    const restoreAuthSessionCreate = stubPrismaMethod(
        prisma.authSession,
        "create",
        (async () => ({ id: "session_teacher_new_1" })) as typeof prisma.authSession.create,
    );
    const restoreAuditLogCreate = stubPrismaMethod(
        prisma.auditLog,
        "create",
        (async () => ({ id: "audit_teacher_refresh_1" })) as typeof prisma.auditLog.create,
    );

    try {
        const response = await request(app)
            .post("/api/auth/refresh")
            .send({ refreshToken: providedRefreshToken })
            .expect(200);

        assert.equal(typeof response.body.accessToken, "string");
        assert.equal(typeof response.body.refreshToken, "string");
        assert.notEqual(response.body.refreshToken, providedRefreshToken);
    } finally {
        restoreAuthSessionFindUnique();
        restoreAuthSessionUpdate();
        restoreTeacherFindUnique();
        restoreAuthSessionCreate();
        restoreAuditLogCreate();
    }
});



test("POST /api/auth/refresh returns 401 when TEACHER from session no longer exists", async () => {
    const providedRefreshToken = "refresh-token-teacher-missing";
    const providedHash = crypto.createHash("sha256").update(providedRefreshToken).digest("hex");

    const restoreAuthSessionFindUnique = stubPrismaMethod(
        prisma.authSession,
        "findUnique",
        (async () => ({
            id: "session_teacher_missing_1",
            userId: "teacher_missing_1",
            userType: "TEACHER",
            tokenHash: providedHash,
            expiresAt: new Date(Date.now() + 60 * 60 * 1000),
            revokedAt: null,
        })) as typeof prisma.authSession.findUnique,
    );
    const restoreAuthSessionUpdate = stubPrismaMethod(
        prisma.authSession,
        "update",
        (async () => ({ id: "session_teacher_missing_1" })) as typeof prisma.authSession.update,
    );
    const restoreTeacherFindUnique = stubPrismaMethod(
        prisma.teacher,
        "findUnique",
        (async () => null) as typeof prisma.teacher.findUnique,
    );

    try {
        const response = await request(app)
            .post("/api/auth/refresh")
            .send({ refreshToken: providedRefreshToken })
            .expect(401);

        assert.equal(response.body.error, "Invalid refresh token");
    } finally {
        restoreAuthSessionFindUnique();
        restoreAuthSessionUpdate();
        restoreTeacherFindUnique();
    }
});



test("POST /api/auth/logout revokes TEACHER sessions", async () => {
    let capturedUserType: string | undefined;

    const restoreAuthSessionUpdateMany = stubPrismaMethod(
        prisma.authSession,
        "updateMany",
        (async (args: unknown) => {
            const where = (args as { where?: { userType?: string } })?.where;
            capturedUserType = where?.userType;
            return { count: 2 };
        }) as typeof prisma.authSession.updateMany,
    );
    const restoreAuditLogCreate = stubPrismaMethod(
        prisma.auditLog,
        "create",
        (async () => ({ id: "audit_teacher_logout_1" })) as typeof prisma.auditLog.create,
    );

    try {
        const token = createAccessToken({
            sub: "teacher_1",
            role: "STAFF",
            schoolId: "school_1",
            userType: "TEACHER",
        });

        const response = await request(app)
            .post("/api/auth/logout")
            .set("authorization", `Bearer ${token}`)
            .send({})
            .expect(200);

        assert.equal(response.body.ok, true);
        assert.equal(capturedUserType, "TEACHER");
    } finally {
        restoreAuthSessionUpdateMany();
        restoreAuditLogCreate();
    }
});



test("GET /api/auth/me returns admin profile for ADMIN_USER token", async () => {
    const restoreAdminUserFindUnique = stubPrismaMethod(
        prisma.adminUser,
        "findUnique",
        (async () => ({
            id: "admin_1",
            name: "Super Admin",
            email: "admin@example.com",
            role: "SUPER_ADMIN",
            schoolId: null,
            passwordHash: "hash",
        })) as typeof prisma.adminUser.findUnique,
    );

    try {
        const token = createAccessToken({
            sub: "admin_1",
            role: "SUPER_ADMIN",
            schoolId: null,
            userType: "ADMIN_USER",
        });

        const response = await request(app)
            .get("/api/auth/me")
            .set("authorization", `Bearer ${token}`)
            .expect(200);

        assert.equal(response.body.id, "admin_1");
        assert.equal(response.body.email, "admin@example.com");
        assert.equal(response.body.role, "SUPER_ADMIN");
    } finally {
        restoreAdminUserFindUnique();
    }
});



test("GET /api/auth/me returns teacher profile for TEACHER token", async () => {
    const restoreTeacherFindUnique = stubPrismaMethod(
        prisma.teacher,
        "findUnique",
        (async () => ({
            id: "teacher_1",
            firstName: "Kojo",
            lastName: "Owusu",
            email: "kojo@example.com",
            schoolId: "school_1",
            status: "ACTIVE",
        })) as typeof prisma.teacher.findUnique,
    );

    try {
        const token = createAccessToken({
            sub: "teacher_1",
            role: "STAFF",
            schoolId: "school_1",
            userType: "TEACHER",
        });

        const response = await request(app)
            .get("/api/auth/me")
            .set("authorization", `Bearer ${token}`)
            .expect(200);

        assert.equal(response.body.id, "teacher_1");
        assert.equal(response.body.role, "STAFF");
        assert.equal(response.body.schoolId, "school_1");
    } finally {
        restoreTeacherFindUnique();
    }
});



test("POST /api/auth/verify-login-otp rejects missing challengeId and otp", async () => {
    const response = await request(app)
        .post("/api/auth/verify-login-otp")
        .send({})
        .expect(400);

    assert.equal(response.body.error, "challengeId and otp are required");
});



test("POST /api/auth/reset-password rejects missing required fields", async () => {
    const response = await request(app)
        .post("/api/auth/reset-password")
        .send({ email: "admin@example.com" })
        .expect(400);

    assert.equal(response.body.error, "email, otp, and newPassword are required");
});



test("POST /api/auth/change-password returns 401 without bearer token", async () => {
    const response = await request(app)
        .post("/api/auth/change-password")
        .send({ challengeId: "abc", otp: "123456", newPassword: "NewPassword@123" })
        .expect(401);

    assert.equal(response.body.error, "Unauthorized: missing bearer token");
});



test("POST /api/auth/verify-login-otp succeeds for ADMIN_USER challenge", async () => {
    const challengeId = "otp_admin_1";
    const otpCode = "123456";

    const restoreOtpFindUnique = stubPrismaMethod(
        prisma.otpToken,
        "findUnique",
        (async () => ({
            id: challengeId,
            phone: "0244000000",
            code: otpCode,
            purpose: "LOGIN_MFA",
            userId: "admin_1",
            userType: "ADMIN_USER",
            expiresAt: new Date(Date.now() + 10 * 60 * 1000),
            usedAt: null,
        })) as typeof prisma.otpToken.findUnique,
    );
    const restoreOtpUpdate = stubPrismaMethod(
        prisma.otpToken,
        "update",
        (async () => ({ id: challengeId })) as typeof prisma.otpToken.update,
    );
    const restoreAdminUserFindUnique = stubPrismaMethod(
        prisma.adminUser,
        "findUnique",
        (async () => ({
            id: "admin_1",
            name: "Admin User",
            email: "admin@example.com",
            role: "SUPER_ADMIN",
            schoolId: null,
            passwordHash: "hash",
        })) as typeof prisma.adminUser.findUnique,
    );
    const restoreAuthSessionCreate = stubPrismaMethod(
        prisma.authSession,
        "create",
        (async () => ({ id: "session_from_otp_admin_1" })) as typeof prisma.authSession.create,
    );

    try {
        const response = await request(app)
            .post("/api/auth/verify-login-otp")
            .send({ challengeId, otp: otpCode })
            .expect(200);

        assert.equal(typeof response.body.accessToken, "string");
        assert.equal(typeof response.body.refreshToken, "string");
        assert.equal(response.body.user.id, "admin_1");
        assert.equal(response.body.user.role, "SUPER_ADMIN");
    } finally {
        restoreOtpFindUnique();
        restoreOtpUpdate();
        restoreAdminUserFindUnique();
        restoreAuthSessionCreate();
    }
});



test("POST /api/auth/verify-login-otp succeeds for TEACHER challenge", async () => {
    const challengeId = "otp_teacher_1";
    const otpCode = "654321";

    const restoreOtpFindUnique = stubPrismaMethod(
        prisma.otpToken,
        "findUnique",
        (async () => ({
            id: challengeId,
            phone: "0244000003",
            code: otpCode,
            purpose: "LOGIN_MFA",
            userId: "teacher_1",
            userType: "TEACHER",
            expiresAt: new Date(Date.now() + 10 * 60 * 1000),
            usedAt: null,
        })) as typeof prisma.otpToken.findUnique,
    );
    const restoreOtpUpdate = stubPrismaMethod(
        prisma.otpToken,
        "update",
        (async () => ({ id: challengeId })) as typeof prisma.otpToken.update,
    );
    const restoreTeacherFindUnique = stubPrismaMethod(
        prisma.teacher,
        "findUnique",
        (async () => ({
            id: "teacher_1",
            firstName: "Kojo",
            lastName: "Owusu",
            email: "kojo@example.com",
            schoolId: "school_1",
            status: "ACTIVE",
        })) as typeof prisma.teacher.findUnique,
    );
    const restoreAuthSessionCreate = stubPrismaMethod(
        prisma.authSession,
        "create",
        (async () => ({ id: "session_from_otp_teacher_1" })) as typeof prisma.authSession.create,
    );

    try {
        const response = await request(app)
            .post("/api/auth/verify-login-otp")
            .send({ challengeId, otp: otpCode })
            .expect(200);

        assert.equal(typeof response.body.accessToken, "string");
        assert.equal(typeof response.body.refreshToken, "string");
        assert.equal(response.body.user.id, "teacher_1");
        assert.equal(response.body.user.role, "STAFF");
    } finally {
        restoreOtpFindUnique();
        restoreOtpUpdate();
        restoreTeacherFindUnique();
        restoreAuthSessionCreate();
    }
});



test("POST /api/auth/verify-login-otp rejects invalid challenge purpose", async () => {
    const restoreOtpFindUnique = stubPrismaMethod(
        prisma.otpToken,
        "findUnique",
        (async () => ({
            id: "otp_wrong_purpose_1",
            code: "123456",
            purpose: "FORGOT_PASSWORD",
            userId: "admin_1",
            userType: "ADMIN_USER",
            expiresAt: new Date(Date.now() + 10 * 60 * 1000),
            usedAt: null,
        })) as typeof prisma.otpToken.findUnique,
    );

    try {
        const response = await request(app)
            .post("/api/auth/verify-login-otp")
            .send({ challengeId: "otp_wrong_purpose_1", otp: "123456" })
            .expect(400);

        assert.equal(response.body.error, "Invalid OTP challenge");
    } finally {
        restoreOtpFindUnique();
    }
});



test("POST /api/auth/verify-login-otp rejects expired OTP", async () => {
    const restoreOtpFindUnique = stubPrismaMethod(
        prisma.otpToken,
        "findUnique",
        (async () => ({
            id: "otp_expired_1",
            code: "123456",
            purpose: "LOGIN_MFA",
            userId: "admin_1",
            userType: "ADMIN_USER",
            expiresAt: new Date(Date.now() - 60 * 1000),
            usedAt: null,
        })) as typeof prisma.otpToken.findUnique,
    );

    try {
        const response = await request(app)
            .post("/api/auth/verify-login-otp")
            .send({ challengeId: "otp_expired_1", otp: "123456" })
            .expect(400);

        assert.equal(response.body.error, "OTP has expired or already been used");
    } finally {
        restoreOtpFindUnique();
    }
});



test("POST /api/auth/verify-login-otp rejects used OTP", async () => {
    const restoreOtpFindUnique = stubPrismaMethod(
        prisma.otpToken,
        "findUnique",
        (async () => ({
            id: "otp_used_1",
            code: "123456",
            purpose: "LOGIN_MFA",
            userId: "admin_1",
            userType: "ADMIN_USER",
            expiresAt: new Date(Date.now() + 10 * 60 * 1000),
            usedAt: new Date(),
        })) as typeof prisma.otpToken.findUnique,
    );

    try {
        const response = await request(app)
            .post("/api/auth/verify-login-otp")
            .send({ challengeId: "otp_used_1", otp: "123456" })
            .expect(400);

        assert.equal(response.body.error, "OTP has expired or already been used");
    } finally {
        restoreOtpFindUnique();
    }
});



test("POST /api/auth/verify-login-otp rejects wrong OTP code", async () => {
    const restoreOtpFindUnique = stubPrismaMethod(
        prisma.otpToken,
        "findUnique",
        (async () => ({
            id: "otp_wrong_code_1",
            code: "123456",
            purpose: "LOGIN_MFA",
            userId: "admin_1",
            userType: "ADMIN_USER",
            expiresAt: new Date(Date.now() + 10 * 60 * 1000),
            usedAt: null,
        })) as typeof prisma.otpToken.findUnique,
    );

    try {
        const response = await request(app)
            .post("/api/auth/verify-login-otp")
            .send({ challengeId: "otp_wrong_code_1", otp: "000000" })
            .expect(400);

        assert.equal(response.body.error, "Invalid OTP code");
    } finally {
        restoreOtpFindUnique();
    }
});



test("POST /api/auth/forgot-password returns generic message for unknown email", async () => {
    const restoreAdminUserFindUnique = stubPrismaMethod(
        prisma.adminUser,
        "findUnique",
        (async () => null) as typeof prisma.adminUser.findUnique,
    );
    const restoreTeacherFindUnique = stubPrismaMethod(
        prisma.teacher,
        "findUnique",
        (async () => null) as typeof prisma.teacher.findUnique,
    );

    try {
        const response = await request(app)
            .post("/api/auth/forgot-password")
            .send({ email: "unknown@example.com" })
            .expect(200);

        assert.equal(
            response.body.message,
            "If an account with that email exists and has a phone registered, an OTP has been sent.",
        );
    } finally {
        restoreAdminUserFindUnique();
        restoreTeacherFindUnique();
    }
});



test("POST /api/auth/forgot-password creates OTP token for known admin with phone", async () => {
    let createdPurpose: string | undefined;
    let createdUserId: string | undefined;

    const restoreAdminUserFindUnique = stubPrismaMethod(
        prisma.adminUser,
        "findUnique",
        (async () => ({
            id: "admin_forgot_1",
            email: "admin.forgot@example.com",
            phone: "0244000010",
            schoolId: "school_1",
            role: "SCHOOL_ADMIN",
            name: "Admin Forgot",
            passwordHash: "hash",
        })) as typeof prisma.adminUser.findUnique,
    );
    const restoreOtpCreate = stubPrismaMethod(
        prisma.otpToken,
        "create",
        (async (args: unknown) => {
            const data = (args as { data?: { purpose?: string; userId?: string } })?.data;
            createdPurpose = data?.purpose;
            createdUserId = data?.userId;
            return { id: "forgot_otp_1" };
        }) as typeof prisma.otpToken.create,
    );

    try {
        const response = await request(app)
            .post("/api/auth/forgot-password")
            .send({ email: "admin.forgot@example.com" })
            .expect(200);

        assert.equal(
            response.body.message,
            "If an account with that email exists and has a phone registered, an OTP has been sent.",
        );
        assert.equal(createdPurpose, "FORGOT_PASSWORD");
        assert.equal(createdUserId, "admin_forgot_1");
    } finally {
        restoreAdminUserFindUnique();
        restoreOtpCreate();
    }
});



test("POST /api/auth/reset-password resets admin password with valid OTP", async () => {
    let updatedAdminId: string | undefined;
    let updatedAdminPasswordHash: string | undefined;

    const restoreAdminUserFindUnique = stubPrismaMethod(
        prisma.adminUser,
        "findUnique",
        (async () => ({
            id: "admin_reset_1",
            email: "admin.reset@example.com",
            phone: "0244000011",
            schoolId: "school_1",
            role: "SCHOOL_ADMIN",
            name: "Admin Reset",
            passwordHash: "old-hash",
        })) as typeof prisma.adminUser.findUnique,
    );
    const restoreOtpFindFirst = stubPrismaMethod(
        prisma.otpToken,
        "findFirst",
        (async () => ({
            id: "forgot_otp_valid_1",
            code: "112233",
            purpose: "FORGOT_PASSWORD",
            userId: "admin_reset_1",
            userType: "ADMIN_USER",
            usedAt: null,
            expiresAt: new Date(Date.now() + 5 * 60 * 1000),
            phone: "0244000011",
        })) as typeof prisma.otpToken.findFirst,
    );
    const restoreOtpUpdate = stubPrismaMethod(
        prisma.otpToken,
        "update",
        (async () => ({ id: "forgot_otp_valid_1" })) as typeof prisma.otpToken.update,
    );
    const restoreAdminUserUpdate = stubPrismaMethod(
        prisma.adminUser,
        "update",
        (async (args: unknown) => {
            const payload = args as {
                where?: { id?: string };
                data?: { passwordHash?: string };
            };
            updatedAdminId = payload.where?.id;
            updatedAdminPasswordHash = payload.data?.passwordHash;
            return { id: payload.where?.id ?? "admin_reset_1" };
        }) as typeof prisma.adminUser.update,
    );

    try {
        const response = await request(app)
            .post("/api/auth/reset-password")
            .send({
                email: "admin.reset@example.com",
                otp: "112233",
                newPassword: "NewPassword@123",
            })
            .expect(200);

        assert.equal(response.body.message, "Password reset successfully. Please log in with your new password.");
        assert.equal(updatedAdminId, "admin_reset_1");
        assert.equal(typeof updatedAdminPasswordHash, "string");
        assert.notEqual(updatedAdminPasswordHash, "NewPassword@123");
    } finally {
        restoreAdminUserFindUnique();
        restoreOtpFindFirst();
        restoreOtpUpdate();
        restoreAdminUserUpdate();
    }
});



test("POST /api/auth/reset-password returns 400 for invalid OTP", async () => {
    const restoreAdminUserFindUnique = stubPrismaMethod(
        prisma.adminUser,
        "findUnique",
        (async () => ({
            id: "admin_reset_2",
            email: "admin.reset2@example.com",
            phone: "0244000012",
            schoolId: "school_1",
            role: "SCHOOL_ADMIN",
            name: "Admin Reset2",
            passwordHash: "old-hash",
        })) as typeof prisma.adminUser.findUnique,
    );
    const restoreOtpFindFirst = stubPrismaMethod(
        prisma.otpToken,
        "findFirst",
        (async () => ({
            id: "forgot_otp_valid_2",
            code: "445566",
            purpose: "FORGOT_PASSWORD",
            userId: "admin_reset_2",
            userType: "ADMIN_USER",
            usedAt: null,
            expiresAt: new Date(Date.now() + 5 * 60 * 1000),
            phone: "0244000012",
        })) as typeof prisma.otpToken.findFirst,
    );

    try {
        const response = await request(app)
            .post("/api/auth/reset-password")
            .send({
                email: "admin.reset2@example.com",
                otp: "000000",
                newPassword: "NewPassword@123",
            })
            .expect(400);

        assert.equal(response.body.error, "Invalid or expired OTP");
    } finally {
        restoreAdminUserFindUnique();
        restoreOtpFindFirst();
    }
});



test("POST /api/auth/request-change-password-otp returns 400 when no phone is registered", async () => {
    const restoreAdminUserFindUnique = stubPrismaMethod(
        prisma.adminUser,
        "findUnique",
        (async (args: unknown) => {
            const where = (args as { where?: { id?: string } })?.where;
            if (where?.id === "admin_no_phone_1") {
                return { phone: null };
            }
            return { id: "admin_no_phone_1" };
        }) as typeof prisma.adminUser.findUnique,
    );

    try {
        const token = createAccessToken({
            sub: "admin_no_phone_1",
            role: "SCHOOL_ADMIN",
            schoolId: "school_1",
            userType: "ADMIN_USER",
        });

        const response = await request(app)
            .post("/api/auth/request-change-password-otp")
            .set("authorization", `Bearer ${token}`)
            .send({})
            .expect(400);

        assert.equal(response.body.error, "No phone number is registered on this account. Contact your administrator.");
    } finally {
        restoreAdminUserFindUnique();
    }
});



test("POST /api/auth/request-change-password-otp sends challenge and enforces cooldown", async () => {
    let createCallCount = 0;

    const restoreAdminUserFindUnique = stubPrismaMethod(
        prisma.adminUser,
        "findUnique",
        (async (args: unknown) => {
            const where = (args as { where?: { id?: string } })?.where;
            if (where?.id === "admin_change_1") {
                return { phone: "0244000013" };
            }
            return { id: "admin_change_1" };
        }) as typeof prisma.adminUser.findUnique,
    );
    const restoreOtpCreate = stubPrismaMethod(
        prisma.otpToken,
        "create",
        (async () => {
            createCallCount += 1;
            return { id: "change_otp_1" };
        }) as typeof prisma.otpToken.create,
    );

    try {
        const token = createAccessToken({
            sub: "admin_change_1",
            role: "SCHOOL_ADMIN",
            schoolId: "school_1",
            userType: "ADMIN_USER",
        });

        const firstResponse = await request(app)
            .post("/api/auth/request-change-password-otp")
            .set("authorization", `Bearer ${token}`)
            .send({})
            .expect(200);

        assert.equal(firstResponse.body.challengeId, "change_otp_1");
        assert.equal(firstResponse.body.message, "OTP sent to your registered phone number.");

        const secondResponse = await request(app)
            .post("/api/auth/request-change-password-otp")
            .set("authorization", `Bearer ${token}`)
            .send({})
            .expect(429);

        assert.equal(typeof secondResponse.body.error, "string");
        assert.ok(secondResponse.body.error.includes("Please wait") || secondResponse.body.error.includes("Too many OTP requests"));
        assert.equal(createCallCount, 1);
    } finally {
        restoreAdminUserFindUnique();
        restoreOtpCreate();
    }
});



test("POST /api/auth/change-password updates password for valid authenticated challenge", async () => {
    let updatedAdminId: string | undefined;
    let updatedAdminPasswordHash: string | undefined;

    const restoreOtpFindUnique = stubPrismaMethod(
        prisma.otpToken,
        "findUnique",
        (async () => ({
            id: "change_challenge_1",
            phone: "0244000014",
            code: "778899",
            purpose: "CHANGE_PASSWORD",
            userId: "admin_change_2",
            userType: "ADMIN_USER",
            expiresAt: new Date(Date.now() + 5 * 60 * 1000),
            usedAt: null,
        })) as typeof prisma.otpToken.findUnique,
    );
    const restoreOtpUpdate = stubPrismaMethod(
        prisma.otpToken,
        "update",
        (async () => ({ id: "change_challenge_1" })) as typeof prisma.otpToken.update,
    );
    const restoreAdminUserUpdate = stubPrismaMethod(
        prisma.adminUser,
        "update",
        (async (args: unknown) => {
            const payload = args as {
                where?: { id?: string };
                data?: { passwordHash?: string };
            };
            updatedAdminId = payload.where?.id;
            updatedAdminPasswordHash = payload.data?.passwordHash;
            return { id: payload.where?.id ?? "admin_change_2" };
        }) as typeof prisma.adminUser.update,
    );

    try {
        const token = createAccessToken({
            sub: "admin_change_2",
            role: "SCHOOL_ADMIN",
            schoolId: "school_1",
            userType: "ADMIN_USER",
        });

        const response = await request(app)
            .post("/api/auth/change-password")
            .set("authorization", `Bearer ${token}`)
            .send({
                challengeId: "change_challenge_1",
                otp: "778899",
                newPassword: "AnotherNewPassword@123",
            })
            .expect(200);

        assert.equal(response.body.message, "Password changed successfully.");
        assert.equal(updatedAdminId, "admin_change_2");
        assert.equal(typeof updatedAdminPasswordHash, "string");
        assert.notEqual(updatedAdminPasswordHash, "AnotherNewPassword@123");
    } finally {
        restoreOtpFindUnique();
        restoreOtpUpdate();
        restoreAdminUserUpdate();
    }
});



test("POST /api/auth/change-password returns 400 for invalid challenge owner", async () => {
    const restoreOtpFindUnique = stubPrismaMethod(
        prisma.otpToken,
        "findUnique",
        (async () => ({
            id: "change_challenge_wrong_owner_1",
            phone: "0244000015",
            code: "101010",
            purpose: "CHANGE_PASSWORD",
            userId: "different_user",
            userType: "ADMIN_USER",
            expiresAt: new Date(Date.now() + 5 * 60 * 1000),
            usedAt: null,
        })) as typeof prisma.otpToken.findUnique,
    );

    try {
        const token = createAccessToken({
            sub: "admin_change_3",
            role: "SCHOOL_ADMIN",
            schoolId: "school_1",
            userType: "ADMIN_USER",
        });

        const response = await request(app)
            .post("/api/auth/change-password")
            .set("authorization", `Bearer ${token}`)
            .send({
                challengeId: "change_challenge_wrong_owner_1",
                otp: "101010",
                newPassword: "AnotherNewPassword@123",
            })
            .expect(400);

        assert.equal(response.body.error, "Invalid OTP challenge");
    } finally {
        restoreOtpFindUnique();
    }
});

