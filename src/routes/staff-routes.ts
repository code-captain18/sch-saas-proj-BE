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
