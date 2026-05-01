import type express from "express";
import prisma from "../lib/prisma.js";
import type { AdminContext, AuditParams, Permission, RequestWithUser } from "../types/app-types.js";

type AdminAcademicDeps = {
    authorize: (req: RequestWithUser, res: express.Response, permission: Permission) => AdminContext | null;
    logAudit: (params: AuditParams) => Promise<void>;
    validateClassTeacherAssignments: (params: {
        schoolId: string;
        classIdToExclude?: string;
        teacherId?: string | null;
        assistantTeacherId?: string | null;
    }) => Promise<{ ok: true } | { ok: false; error: string }>;
};

export function createAdminAcademicController(deps: AdminAcademicDeps) {
    const { authorize, logAudit, validateClassTeacherAssignments } = deps;
    const paramToString = (value: string | string[] | undefined) => (Array.isArray(value) ? value[0] : value);

    const listClasses = async (req: RequestWithUser, res: express.Response) => {
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
    };

    const createClass = async (req: RequestWithUser, res: express.Response) => {
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
    };

    const listSubjects = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "subjects:read");
        if (!context) return;

        const where = context.schoolId ? { schoolId: context.schoolId } : undefined;
        const subjects = await prisma.subject.findMany({ where, orderBy: { createdAt: "desc" } });
        res.json(subjects);
    };

    const createSubject = async (req: RequestWithUser, res: express.Response) => {
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
    };

    const linkClassSubject = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "subjects:write");
        if (!context) return;

        const classId = paramToString(req.params.classId);
        if (!classId) {
            res.status(400).json({ error: "classId is required" });
            return;
        }

        const link = await prisma.classSubject.create({
            data: {
                classId,
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
            metadata: { classId, subjectId: req.body.subjectId },
        });
        res.status(201).json(link);
    };

    const bulkAssignSubjects = async (req: RequestWithUser, res: express.Response) => {
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
    };

    const listTeachingAssignments = async (req: RequestWithUser, res: express.Response) => {
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
    };

    const createTeachingAssignment = async (req: RequestWithUser, res: express.Response) => {
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
    };

    const deleteTeachingAssignment = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "teachers:write");
        if (!context) return;

        const assignmentId = paramToString(req.params.id);
        if (!assignmentId) {
            res.status(400).json({ error: "Teaching assignment id is required" });
            return;
        }

        const existing = await prisma.teachingAssignment.findUnique({ where: { id: assignmentId } });
        if (!existing) {
            res.status(404).json({ error: "Teaching assignment not found" });
            return;
        }
        if (context.schoolId && existing.schoolId !== context.schoolId) {
            res.status(403).json({ error: "Forbidden" });
            return;
        }

        await prisma.teachingAssignment.delete({ where: { id: assignmentId } });
        await logAudit({
            req,
            action: "TEACHING_ASSIGNMENT_DELETE",
            entityType: "TeachingAssignment",
            entityId: assignmentId,
            schoolId: existing.schoolId,
            actorUserId: context.userId,
            actorRole: context.role,
            metadata: { teacherId: existing.teacherId, classId: existing.classId, subjectId: existing.subjectId },
        });

        res.json({ ok: true });
    };

    return {
        listClasses,
        createClass,
        listSubjects,
        createSubject,
        linkClassSubject,
        bulkAssignSubjects,
        listTeachingAssignments,
        createTeachingAssignment,
        deleteTeachingAssignment,
    };
}
