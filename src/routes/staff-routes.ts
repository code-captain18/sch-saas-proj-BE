import { Prisma } from "@prisma/client";
import type express from "express";
import prisma from "../lib/prisma.js";
import { getGuardianPhones, sendSms } from "../lib/sms.js";
import type { AuditParams, Permission, RequestWithUser, Role } from "../types/app-types.js";

type TeacherRestriction = {
    teacherId: string;
    schoolId: string | null;
    allowedClassIds: string[];
    taughtSubject: string | null;
    teachingAssignments: Array<{ classId: string; subjectId: string }>;
};

type StaffContext = {
    role: Role;
    schoolId: string | null;
    userId: string;
};

type StaffRouteDeps = {
    authorize: (req: RequestWithUser, res: express.Response, permission: Permission) => StaffContext | null;
    getTeacherRestriction: (req: RequestWithUser, schoolId: string | null) => Promise<TeacherRestriction | null>;
    hasTeacherSubjectAccess: (taughtSubject: string | null, subject: { name: string; code: string }) => boolean;
    hasExplicitTeachingAssignment: (
        assignments: Array<{ classId: string; subjectId: string }>,
        classId: string,
        subjectId: string,
    ) => boolean;
    logAudit: (params: AuditParams) => Promise<void>;
};

const LESSON_PLAN_PREFIX = "LESSON_PLAN::";

type LessonPlanMeta = {
    subject?: string;
    objectives?: string;
    activities?: string;
    materials?: string;
    assessment?: string;
};

function toStringValue(value: unknown) {
    if (typeof value !== "string") return undefined;
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
}

function buildLessonPlanDescription(meta: LessonPlanMeta) {
    return `${LESSON_PLAN_PREFIX}${JSON.stringify(meta)}`;
}

function parseLessonPlanDescription(description: string | null | undefined) {
    if (!description || !description.startsWith(LESSON_PLAN_PREFIX)) {
        return null;
    }

    const payload = description.slice(LESSON_PLAN_PREFIX.length);
    try {
        const parsed = JSON.parse(payload) as LessonPlanMeta;
        return {
            subject: toStringValue(parsed.subject) ?? "",
            objectives: toStringValue(parsed.objectives) ?? "",
            activities: toStringValue(parsed.activities) ?? "",
            materials: toStringValue(parsed.materials) ?? "",
            assessment: toStringValue(parsed.assessment) ?? "",
        };
    } catch {
        return null;
    }
}

function getPeriodWindow(period: "daily" | "weekly", dateInput?: string) {
    const baseDate = dateInput ? new Date(dateInput) : new Date();
    if (Number.isNaN(baseDate.getTime())) {
        return null;
    }

    if (period === "weekly") {
        const start = new Date(baseDate);
        const day = start.getDay();
        const diffToMonday = day === 0 ? -6 : 1 - day;
        start.setDate(start.getDate() + diffToMonday);
        start.setHours(0, 0, 0, 0);

        const end = new Date(start);
        end.setDate(end.getDate() + 7);
        return { start, end };
    }

    const start = new Date(baseDate);
    start.setHours(0, 0, 0, 0);
    const end = new Date(start);
    end.setDate(end.getDate() + 1);
    return { start, end };
}

export function registerStaffRoutes(app: express.Express, deps: StaffRouteDeps) {
    const {
        authorize,
        getTeacherRestriction,
        hasTeacherSubjectAccess,
        hasExplicitTeachingAssignment,
        logAudit,
    } = deps;

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
            const errorCode =
                error instanceof Prisma.PrismaClientKnownRequestError
                    ? error.code
                    : (typeof error === "object" && error !== null && "code" in error
                        ? String((error as { code?: unknown }).code)
                        : undefined);

            if (errorCode === "P2002") {
                res.status(409).json({ error: "Score already exists for this student, subject, term, and academic year" });
                return;
            }
            console.error("Failed to create score:", error);
            res.status(500).json({ error: "Failed to create score" });
        }
    });

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

    app.get("/api/staff/assignments", async (req: RequestWithUser, res) => {
        const context = authorize(req, res, "students:read");
        if (!context) return;

        try {
            const classId = typeof req.query.classId === "string" ? req.query.classId : undefined;

            const where: Prisma.AssignmentWhereInput = {
                schoolId: context.schoolId ?? "",
                ...(classId ? { classId } : {}),
                NOT: {
                    description: {
                        startsWith: LESSON_PLAN_PREFIX,
                    },
                },
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

    app.get("/api/staff/lesson-plans", async (req: RequestWithUser, res) => {
        const context = authorize(req, res, "students:read");
        if (!context) return;

        try {
            const classId = typeof req.query.classId === "string" ? req.query.classId : undefined;
            const from = typeof req.query.from === "string" ? req.query.from : undefined;
            const to = typeof req.query.to === "string" ? req.query.to : undefined;

            const restriction = await getTeacherRestriction(req, context.schoolId);
            if (restriction && restriction.allowedClassIds.length === 0) {
                res.json([]);
                return;
            }

            if (restriction && classId && !restriction.allowedClassIds.includes(classId)) {
                res.status(403).json({ error: "Forbidden: class not assigned to this teacher" });
                return;
            }

            const effectiveClassIds = restriction
                ? (classId ? [classId] : restriction.allowedClassIds)
                : (classId ? [classId] : undefined);

            const plans = await prisma.assignment.findMany({
                where: {
                    schoolId: context.schoolId ?? "",
                    ...(effectiveClassIds ? { classId: { in: effectiveClassIds } } : {}),
                    description: { startsWith: LESSON_PLAN_PREFIX },
                    ...(from || to
                        ? {
                            dueDate: {
                                ...(from ? { gte: new Date(from) } : {}),
                                ...(to ? { lte: new Date(to) } : {}),
                            },
                        }
                        : {}),
                },
                include: {
                    class: {
                        select: {
                            id: true,
                            name: true,
                            grade: true,
                        },
                    },
                },
                orderBy: [{ dueDate: "desc" }, { createdAt: "desc" }],
                take: 120,
            });

            const response = plans
                .map((plan) => {
                    const meta = parseLessonPlanDescription(plan.description);
                    if (!meta) return null;

                    return {
                        id: plan.id,
                        title: plan.title,
                        classId: plan.classId,
                        schoolId: plan.schoolId,
                        plannedFor: plan.dueDate,
                        createdAt: plan.createdAt,
                        updatedAt: plan.updatedAt,
                        class: plan.class,
                        subject: meta.subject,
                        objectives: meta.objectives,
                        activities: meta.activities,
                        materials: meta.materials,
                        assessment: meta.assessment,
                    };
                })
                .filter((item): item is NonNullable<typeof item> => item !== null);

            res.json(response);
        } catch (error) {
            console.error("Failed to get lesson plans:", error);
            res.status(500).json({ error: "Failed to get lesson plans" });
        }
    });

    app.post("/api/staff/lesson-plans", async (req: RequestWithUser, res) => {
        const context = authorize(req, res, "students:read");
        if (!context) return;
        if (context.role === "VIEWER") {
            res.status(403).json({ error: "Forbidden: insufficient role permissions" });
            return;
        }

        try {
            const title = toStringValue(req.body.title);
            const classId = toStringValue(req.body.classId);
            const plannedForRaw = toStringValue(req.body.plannedFor) ?? toStringValue(req.body.date);

            if (!title || !classId || !plannedForRaw) {
                res.status(400).json({ error: "title, classId, and plannedFor are required" });
                return;
            }

            const plannedFor = new Date(plannedForRaw);
            if (Number.isNaN(plannedFor.getTime())) {
                res.status(400).json({ error: "Invalid plannedFor date" });
                return;
            }

            const restriction = await getTeacherRestriction(req, context.schoolId);
            if (restriction && !restriction.allowedClassIds.includes(classId)) {
                res.status(403).json({ error: "Forbidden: class not assigned to this teacher" });
                return;
            }

            const schoolClass = await prisma.class.findFirst({
                where: {
                    id: classId,
                    schoolId: context.schoolId ?? "",
                },
                select: {
                    id: true,
                },
            });

            if (!schoolClass) {
                res.status(400).json({ error: "Invalid class for this school" });
                return;
            }

            const payload: LessonPlanMeta = {
                subject: toStringValue(req.body.subject),
                objectives: toStringValue(req.body.objectives),
                activities: toStringValue(req.body.activities),
                materials: toStringValue(req.body.materials),
                assessment: toStringValue(req.body.assessment),
            };

            const created = await prisma.assignment.create({
                data: {
                    title,
                    classId,
                    schoolId: context.schoolId ?? "",
                    dueDate: plannedFor,
                    description: buildLessonPlanDescription(payload),
                },
                include: {
                    class: {
                        select: {
                            id: true,
                            name: true,
                            grade: true,
                        },
                    },
                },
            });

            await logAudit({
                req,
                action: "LESSON_PLAN_CREATE",
                entityType: "Assignment",
                entityId: created.id,
                schoolId: context.schoolId,
                actorUserId: context.userId,
                actorRole: context.role,
                status: "SUCCESS",
                metadata: { title, classId, plannedFor: plannedFor.toISOString() },
            });

            const meta = parseLessonPlanDescription(created.description);
            res.status(201).json({
                id: created.id,
                title: created.title,
                classId: created.classId,
                schoolId: created.schoolId,
                plannedFor: created.dueDate,
                createdAt: created.createdAt,
                updatedAt: created.updatedAt,
                class: created.class,
                subject: meta?.subject ?? "",
                objectives: meta?.objectives ?? "",
                activities: meta?.activities ?? "",
                materials: meta?.materials ?? "",
                assessment: meta?.assessment ?? "",
            });
        } catch (error) {
            console.error("Failed to create lesson plan:", error);
            res.status(500).json({ error: "Failed to create lesson plan" });
        }
    });

    app.delete("/api/staff/lesson-plans/:id", async (req: RequestWithUser, res) => {
        const context = authorize(req, res, "students:read");
        if (!context) return;
        if (context.role === "VIEWER") {
            res.status(403).json({ error: "Forbidden: insufficient role permissions" });
            return;
        }

        try {
            const id = String(req.params.id);
            const existing = await prisma.assignment.findUnique({
                where: { id },
                select: {
                    id: true,
                    schoolId: true,
                    classId: true,
                    description: true,
                },
            });

            if (!existing || existing.schoolId !== (context.schoolId ?? "")) {
                res.status(404).json({ error: "Lesson plan not found" });
                return;
            }

            if (!existing.description?.startsWith(LESSON_PLAN_PREFIX)) {
                res.status(400).json({ error: "Record is not a lesson plan" });
                return;
            }

            const restriction = await getTeacherRestriction(req, context.schoolId);
            if (restriction && !restriction.allowedClassIds.includes(existing.classId)) {
                res.status(403).json({ error: "Forbidden: class not assigned to this teacher" });
                return;
            }

            await prisma.assignment.delete({ where: { id } });

            await logAudit({
                req,
                action: "LESSON_PLAN_DELETE",
                entityType: "Assignment",
                entityId: id,
                schoolId: context.schoolId,
                actorUserId: context.userId,
                actorRole: context.role,
                status: "SUCCESS",
            });

            res.json({ ok: true });
        } catch (error) {
            console.error("Failed to delete lesson plan:", error);
            res.status(500).json({ error: "Failed to delete lesson plan" });
        }
    });

    app.get("/api/staff/progress-reports", async (req: RequestWithUser, res) => {
        const context = authorize(req, res, "students:read");
        if (!context) return;

        try {
            const periodRaw = typeof req.query.period === "string" ? req.query.period : "daily";
            const period = periodRaw === "weekly" ? "weekly" : "daily";
            const classId = typeof req.query.classId === "string" ? req.query.classId : undefined;
            const dateInput = typeof req.query.date === "string" ? req.query.date : undefined;
            const periodWindow = getPeriodWindow(period, dateInput);

            if (!periodWindow) {
                res.status(400).json({ error: "Invalid date query parameter" });
                return;
            }

            const restriction = await getTeacherRestriction(req, context.schoolId);
            if (restriction && restriction.allowedClassIds.length === 0) {
                res.json({
                    period,
                    startDate: periodWindow.start.toISOString(),
                    endDateExclusive: periodWindow.end.toISOString(),
                    reports: [],
                });
                return;
            }

            if (restriction && classId && !restriction.allowedClassIds.includes(classId)) {
                res.status(403).json({ error: "Forbidden: class not assigned to this teacher" });
                return;
            }

            const classIds = restriction
                ? (classId ? [classId] : restriction.allowedClassIds)
                : (classId ? [classId] : undefined);

            const [studentRows, attendanceRows, scoreRows] = await Promise.all([
                prisma.student.findMany({
                    where: {
                        schoolId: context.schoolId ?? "",
                        status: "ACTIVE",
                        ...(classIds ? { classId: { in: classIds } } : {}),
                    },
                    select: {
                        id: true,
                        firstName: true,
                        otherNames: true,
                        lastName: true,
                        classId: true,
                        class: {
                            select: {
                                id: true,
                                name: true,
                                grade: true,
                            },
                        },
                    },
                    orderBy: [{ classId: "asc" }, { firstName: "asc" }, { lastName: "asc" }],
                }),
                prisma.attendance.findMany({
                    where: {
                        schoolId: context.schoolId ?? "",
                        ...(classIds ? { classId: { in: classIds } } : {}),
                        date: {
                            gte: periodWindow.start,
                            lt: periodWindow.end,
                        },
                    },
                    select: {
                        studentId: true,
                        status: true,
                    },
                }),
                prisma.score.findMany({
                    where: {
                        schoolId: context.schoolId ?? "",
                        ...(classIds ? { classId: { in: classIds } } : {}),
                        createdAt: {
                            gte: periodWindow.start,
                            lt: periodWindow.end,
                        },
                    },
                    select: {
                        studentId: true,
                        score: true,
                        maxScore: true,
                        createdAt: true,
                    },
                    orderBy: {
                        createdAt: "desc",
                    },
                }),
            ]);

            const attendanceByStudent = new Map<string, { totalMarked: number; presentLikeCount: number }>();
            for (const row of attendanceRows) {
                const bucket = attendanceByStudent.get(row.studentId) ?? { totalMarked: 0, presentLikeCount: 0 };
                bucket.totalMarked += 1;
                if (row.status === "PRESENT" || row.status === "LATE" || row.status === "EXCUSED") {
                    bucket.presentLikeCount += 1;
                }
                attendanceByStudent.set(row.studentId, bucket);
            }

            const scoresByStudent = new Map<string, Array<{ score: number; maxScore: number; createdAt: Date }>>();
            for (const row of scoreRows) {
                const bucket = scoresByStudent.get(row.studentId) ?? [];
                bucket.push({
                    score: Number(row.score),
                    maxScore: Number(row.maxScore),
                    createdAt: row.createdAt,
                });
                scoresByStudent.set(row.studentId, bucket);
            }

            const reports = studentRows.map((student) => {
                const attendance = attendanceByStudent.get(student.id) ?? { totalMarked: 0, presentLikeCount: 0 };
                const scores = scoresByStudent.get(student.id) ?? [];
                const averageScore = scores.length > 0
                    ? scores.reduce((sum, item) => sum + item.score, 0) / scores.length
                    : null;
                const latest = scores[0] ?? null;
                const attendanceRate = attendance.totalMarked > 0
                    ? (attendance.presentLikeCount / attendance.totalMarked) * 100
                    : null;

                let status: "ON_TRACK" | "NEEDS_SUPPORT" | "WATCH" = "WATCH";
                if (attendanceRate !== null && averageScore !== null) {
                    if (attendanceRate >= 85 && averageScore >= 60) status = "ON_TRACK";
                    else if (attendanceRate < 70 || averageScore < 45) status = "NEEDS_SUPPORT";
                }

                const name = `${student.firstName}${student.otherNames ? ` ${student.otherNames}` : ""} ${student.lastName}`;

                return {
                    studentId: student.id,
                    studentName: name,
                    classId: student.classId,
                    className: student.class?.name ?? "Unassigned",
                    period,
                    periodStart: periodWindow.start,
                    periodEndExclusive: periodWindow.end,
                    attendance: {
                        totalMarked: attendance.totalMarked,
                        presentLikeCount: attendance.presentLikeCount,
                        rate: attendanceRate,
                    },
                    performance: {
                        assessmentsCount: scores.length,
                        averageScore,
                        latestScore: latest?.score ?? null,
                        latestMaxScore: latest?.maxScore ?? null,
                        latestRecordedAt: latest?.createdAt ?? null,
                    },
                    status,
                };
            });

            res.json({
                period,
                startDate: periodWindow.start.toISOString(),
                endDateExclusive: periodWindow.end.toISOString(),
                reports,
            });
        } catch (error) {
            console.error("Failed to get progress reports:", error);
            res.status(500).json({ error: "Failed to get progress reports" });
        }
    });

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
}
