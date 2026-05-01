import type express from "express";
import type { Prisma } from "@prisma/client";
import prisma from "./prisma.js";
import type { AuditParams } from "../types/app-types.js";

function getClientIp(req: express.Request) {
    const forwardedFor = req.header("x-forwarded-for");
    if (forwardedFor) {
        return forwardedFor.split(",")[0]?.trim() ?? null;
    }

    return req.socket.remoteAddress ?? null;
}

export function parseDateParam(value: unknown) {
    if (typeof value !== "string" || !value) return null;
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function csvEscape(value: unknown) {
    const stringValue = value === null || value === undefined ? "" : String(value);
    return `"${stringValue.replace(/"/g, '""')}"`;
}

export function buildAuditCsv(logs: Array<{
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

export async function logAudit(params: AuditParams) {
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
