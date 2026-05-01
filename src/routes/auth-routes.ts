import bcrypt from "bcryptjs";
import type express from "express";
import {
    clearLimiterKey,
    consumeCooldown,
    consumeRateLimit,
    getRequestIp,
} from "../lib/otp-security.js";
import prisma from "../lib/prisma.js";
import { generateOtp, otpExpiresAt, sendSms } from "../lib/sms.js";
import { validateBody } from "../lib/middleware.js";
import { canSchoolAccess, isSubscriptionEnforcementEnabled } from "../lib/subscription.js";
import { loginSchema, refreshTokenSchema } from "../lib/validations.js";
import type { AuditParams, RequestWithUser, Role } from "../types/app-types.js";

type AuthRouteDeps = {
    createAccessToken: (user: { id: string; role: Role; schoolId: string | null; userType?: "ADMIN_USER" | "TEACHER" }) => string;
    createRefreshSession: (userId: string, userType?: "ADMIN_USER" | "TEACHER") => Promise<string>;
    hashToken: (token: string) => string;
    authenticate: (req: RequestWithUser, res: express.Response, next: express.NextFunction) => void | Promise<void>;
    logAudit: (params: AuditParams) => Promise<void>;
    otpSendWindowMs: number;
    otpSendCooldownMs: number;
    otpVerifyWindowMs: number;
    otpSendIpLimit: number;
    otpSendUserLimit: number;
    otpVerifyIpLimit: number;
    otpVerifyChallengeLimit: number;
    otpSendIpBlockMs: number;
    otpSendUserBlockMs: number;
    otpVerifyBlockMs: number;
};

export function registerAuthRoutes(app: express.Express, deps: AuthRouteDeps) {
    const {
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
    } = deps;

    const ensureSchoolAccess = async (schoolId: string | null) => {
        if (!isSubscriptionEnforcementEnabled()) {
            return { allowed: true, reason: null as string | null };
        }

        if (!schoolId) {
            return { allowed: true, reason: null as string | null };
        }

        const school = await prisma.school.findUnique({
            where: { id: schoolId },
            select: {
                isActive: true,
                createdAt: true,
                subscriptionStartedAt: true,
                subscriptionTrialEndsAt: true,
                subscriptionPaidUntil: true,
            },
        });

        if (!school) {
            return { allowed: false, reason: "School not found" };
        }

        const access = canSchoolAccess(school);
        return {
            allowed: access.allowed,
            reason: access.reason,
        };
    };

    app.post("/api/auth/login", validateBody(loginSchema), async (req, res) => {
        const { email, password } = req.body;

        const user = await prisma.adminUser.findUnique({ where: { email } });
        if (user) {
            const schoolAccess = await ensureSchoolAccess(user.schoolId);
            if (!schoolAccess.allowed) {
                res.status(403).json({ error: schoolAccess.reason ?? "School access is blocked" });
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

        const teacherSchoolAccess = await ensureSchoolAccess(teacher.schoolId);
        if (!teacherSchoolAccess.allowed) {
            res.status(403).json({ error: teacherSchoolAccess.reason ?? "School access is blocked" });
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

            const teacherSchoolAccess = await ensureSchoolAccess(teacher.schoolId);
            if (!teacherSchoolAccess.allowed) {
                res.status(403).json({ error: teacherSchoolAccess.reason ?? "School access is blocked" });
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

        const adminSchoolAccess = await ensureSchoolAccess(adminUser.schoolId);
        if (!adminSchoolAccess.allowed) {
            res.status(403).json({ error: adminSchoolAccess.reason ?? "School access is blocked" });
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

            const teacherSchoolAccess = await ensureSchoolAccess(teacher.schoolId);
            if (!teacherSchoolAccess.allowed) {
                res.status(403).json({ error: teacherSchoolAccess.reason ?? "School access is blocked" });
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

        const adminSchoolAccess = await ensureSchoolAccess(adminUser.schoolId);
        if (!adminSchoolAccess.allowed) {
            res.status(403).json({ error: adminSchoolAccess.reason ?? "School access is blocked" });
            return;
        }

        const accessToken = createAccessToken({ id: adminUser.id, role: adminUser.role as Role, schoolId: adminUser.schoolId, userType: "ADMIN_USER" });
        const refreshToken = await createRefreshSession(adminUser.id, "ADMIN_USER");
        res.json({ accessToken, refreshToken, user: { id: adminUser.id, name: adminUser.name, email: adminUser.email, role: adminUser.role, schoolId: adminUser.schoolId } });
    });

    app.post("/api/auth/forgot-password", async (req, res) => {
        const { email } = req.body ?? {};
        if (!email || typeof email !== "string") {
            res.status(400).json({ error: "email is required" });
            return;
        }

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
}
