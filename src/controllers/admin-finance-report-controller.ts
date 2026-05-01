import { Prisma } from "@prisma/client";
import type express from "express";
import prisma from "../lib/prisma.js";
import { getGuardianPhones, sendSms } from "../lib/sms.js";
import type { AdminContext, AuditParams, FeeLineItem, Permission, RequestWithUser } from "../types/app-types.js";

type AdminFinanceReportDeps = {
    authorize: (req: RequestWithUser, res: express.Response, permission: Permission) => AdminContext | null;
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

export function createAdminFinanceReportController(deps: AdminFinanceReportDeps) {
    const { authorize, logAudit, sumFeeItems, buildAuditCsv, parseDateParam } = deps;

    const listFeeInvoices = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "fees:read");
        if (!context) return;

        const where = context.schoolId ? { schoolId: context.schoolId } : undefined;
        const invoices = await prisma.feeInvoice.findMany({
            where,
            include: {
                student: { include: { class: true } },
                feeStructure: { include: { class: true } },
                payments: true,
            },
            orderBy: { createdAt: "desc" },
        });
        res.json(invoices);
    };

    const listFeeStructures = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "fees:read");
        if (!context) return;

        const where = context.schoolId ? { schoolId: context.schoolId } : undefined;
        const structures = await prisma.feeStructure.findMany({
            where,
            include: { class: true },
            orderBy: [{ academicYear: "desc" }, { term: "asc" }, { createdAt: "desc" }],
        });

        res.json(structures);
    };

    const createFeeStructure = async (req: RequestWithUser, res: express.Response) => {
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
            include: { class: true },
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
    };

    const createFeeInvoice = async (req: RequestWithUser, res: express.Response) => {
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
                student: { include: { class: true } },
                feeStructure: { include: { class: true } },
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

        const invoiceGuardianPhones = getGuardianPhones(invoice.student.guardianInfo);
        const invoiceStudentName = [invoice.student.firstName, invoice.student.lastName].filter(Boolean).join(" ");
        const invoiceDue = invoice.dueDate.toLocaleDateString("en-GB");
        for (const phone of invoiceGuardianPhones) {
            sendSms(phone, `Dear Guardian, a fee invoice of GHS ${Number(invoice.amount).toFixed(2)} has been raised for ${invoiceStudentName} (${invoice.term.replace("_", " ")}, ${invoice.academicYear ?? ""}). Due: ${invoiceDue}. Contact the school for details.`);
        }

        res.status(201).json(invoice);
    };

    const generateFeeInvoices = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "fees:write");
        if (!context) return;

        const structure = await prisma.feeStructure.findUnique({
            where: { id: req.body.feeStructureId },
            include: { class: true },
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

        const students = await prisma.student.findMany({ where: studentWhere, include: { class: true } });
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
                            student: { include: { class: true } },
                            feeStructure: { include: { class: true } },
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
    };

    const createFeePayment = async (req: RequestWithUser, res: express.Response) => {
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
        const existingInvoice = await prisma.feeInvoice.findUnique({ where: { id: invoiceId }, include: { payments: true } });

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

        const payment = await prisma.feePayment.create({ data: { invoiceId, amount: paymentAmount, method: paymentMethod, reference } });

        const invoice = await prisma.feeInvoice.findUnique({
            where: { id: invoiceId },
            include: {
                payments: true,
                student: { include: { class: true } },
                feeStructure: { include: { class: true } },
            },
        });

        if (invoice) {
            const paidAmount = invoice.payments.reduce((sum, item) => sum + Number(item.amount), 0);
            const totalAmount = Number(invoice.amount);
            const status = paidAmount >= totalAmount ? "PAID" : paidAmount > 0 ? "PARTIALLY_PAID" : "PENDING";

            await prisma.feeInvoice.update({ where: { id: invoice.id }, data: { status } });

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

        res.status(201).json({ payment, invoice });
    };

    const reportOverview = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "reports:read");
        if (!context) return;

        const schoolFilter = context.schoolId ? { schoolId: context.schoolId } : undefined;
        const [students, teachers, classes, subjects, invoices, payments] = await Promise.all([
            prisma.student.count({ where: schoolFilter }),
            prisma.teacher.count({ where: schoolFilter }),
            prisma.class.count({ where: schoolFilter }),
            prisma.subject.count({ where: schoolFilter }),
            prisma.feeInvoice.aggregate({ where: schoolFilter, _sum: { amount: true } }),
            prisma.feePayment.aggregate({ where: schoolFilter ? { invoice: { schoolId: schoolFilter.schoolId } } : undefined, _sum: { amount: true } }),
        ]);

        const totalInvoiced = Number(invoices._sum.amount ?? 0);
        const totalCollected = Number(payments._sum.amount ?? 0);
        const outstandingAmount = Math.max(totalInvoiced - totalCollected, 0);

        res.json({ students, teachers, classes, subjects, totalInvoiced, totalCollected, outstandingAmount });
    };

    const listUsers = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "reports:read");
        if (!context) return;

        const where = context.schoolId ? { schoolId: context.schoolId } : undefined;
        const users = await prisma.adminUser.findMany({ where, orderBy: { createdAt: "desc" } });
        res.json(users);
    };

    const listAuditLogs = async (req: RequestWithUser, res: express.Response) => {
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
                    select: { id: true, name: true, email: true, role: true },
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
    };

    const listAdminAttendance = async (req: RequestWithUser, res: express.Response) => {
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
                orderBy: [{ date: "desc" }, { createdAt: "desc" }],
            });

            res.json(attendance);
        } catch (error) {
            console.error("Failed to get admin attendance:", error);
            res.status(500).json({ error: "Failed to get attendance" });
        }
    };

    return {
        listFeeInvoices,
        listFeeStructures,
        createFeeStructure,
        createFeeInvoice,
        generateFeeInvoices,
        createFeePayment,
        reportOverview,
        listUsers,
        listAuditLogs,
        listAdminAttendance,
    };
}
