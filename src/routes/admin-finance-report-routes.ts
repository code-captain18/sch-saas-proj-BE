import type express from "express";
import type { Prisma } from "@prisma/client";
import { z } from "zod";
import { createAdminFinanceReportController } from "../controllers/admin-finance-report-controller.js";
import type { AdminContext, AuditParams, FeeLineItem, Permission, RequestWithUser } from "../types/app-types.js";

type RegisterAdminFinanceReportRoutesDeps = {
    authenticate: (req: RequestWithUser, res: express.Response, next: express.NextFunction) => Promise<void> | void;
    authorize: (req: RequestWithUser, res: express.Response, permission: Permission) => AdminContext | null;
    validateBody: (schema: z.ZodTypeAny) => (req: express.Request, res: express.Response, next: express.NextFunction) => Promise<unknown> | unknown;
    validateQuery: (schema: z.ZodTypeAny) => (req: express.Request, res: express.Response, next: express.NextFunction) => Promise<unknown> | unknown;
    feeStructureCreateSchema: z.ZodTypeAny;
    feeInvoiceCreateSchema: z.ZodTypeAny;
    invoiceBulkGenerateSchema: z.ZodTypeAny;
    logAudit: (params: AuditParams) => Promise<void>;
    sumFeeItems: (items: FeeLineItem[]) => number;
    buildAuditCsv: (logs: Array<{
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
    }>) => string;
    parseDateParam: (value: unknown) => Date | null;
};

const feePaymentCreateSchema = z.object({
    invoiceId: z.string().uuid(),
    amount: z.number().positive(),
    method: z.enum(["CASH", "BANK_TRANSFER", "CARD", "ONLINE"]),
    reference: z.string().trim().min(1).max(120).optional(),
});

const adminAuditLogsQuerySchema = z.object({
    limit: z.number().int().positive().optional(),
    action: z.string().trim().min(1).optional(),
    status: z.enum(["SUCCESS", "FAILED"]).optional(),
    from: z.string().datetime().optional(),
    to: z.string().datetime().optional(),
    format: z.enum(["json", "csv"]).optional(),
});

const adminAttendanceQuerySchema = z.object({
    classId: z.string().uuid().optional(),
    from: z.string().datetime().optional(),
    to: z.string().datetime().optional(),
});

export function registerAdminFinanceReportRoutes(app: express.Express, deps: RegisterAdminFinanceReportRoutesDeps) {
    const controller = createAdminFinanceReportController({
        authorize: deps.authorize,
        logAudit: deps.logAudit,
        sumFeeItems: deps.sumFeeItems,
        buildAuditCsv: deps.buildAuditCsv,
        parseDateParam: deps.parseDateParam,
    });

    app.get("/api/admin/fees/invoices", deps.authenticate, controller.listFeeInvoices);
    app.get("/api/admin/fees/structures", deps.authenticate, controller.listFeeStructures);
    app.post("/api/admin/fees/structures", deps.authenticate, deps.validateBody(deps.feeStructureCreateSchema), controller.createFeeStructure);
    app.post("/api/admin/fees/invoices", deps.authenticate, deps.validateBody(deps.feeInvoiceCreateSchema), controller.createFeeInvoice);
    app.post("/api/admin/fees/invoices/generate", deps.authenticate, deps.validateBody(deps.invoiceBulkGenerateSchema), controller.generateFeeInvoices);
    app.post("/api/admin/fees/payments", deps.authenticate, deps.validateBody(feePaymentCreateSchema), controller.createFeePayment);
    app.get("/api/admin/reports/overview", deps.authenticate, controller.reportOverview);
    app.get("/api/admin/users", deps.authenticate, controller.listUsers);
    app.get("/api/admin/audit-logs", deps.authenticate, deps.validateQuery(adminAuditLogsQuerySchema), controller.listAuditLogs);
    app.get("/api/admin/attendance", deps.authenticate, deps.validateQuery(adminAttendanceQuerySchema), controller.listAdminAttendance);
}
