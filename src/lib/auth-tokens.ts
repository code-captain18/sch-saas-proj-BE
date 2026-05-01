import crypto from "crypto";
import jwt from "jsonwebtoken";
import prisma from "./prisma.js";
import type { Role } from "../types/app-types.js";

const jwtSecret = process.env.JWT_SECRET ?? process.env.AUTH_JWT_SECRET ?? "dev-only-change-me";
const accessTokenTtl = "15m";
const refreshTokenTtlDays = 7;

export function hashToken(token: string) {
    return crypto.createHash("sha256").update(token).digest("hex");
}

export function createAccessToken(user: { id: string; role: Role; schoolId: string | null; userType?: "ADMIN_USER" | "TEACHER" }) {
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

export async function createRefreshSession(userId: string, userType: "ADMIN_USER" | "TEACHER" = "ADMIN_USER") {
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
