import bcrypt from "bcryptjs";
import type express from "express";
import { Prisma } from "@prisma/client";
import prisma from "../lib/prisma.js";
import { createTeacherSchema } from "../lib/validations.js";
import type { AdminContext, AuditParams, Permission, RequestWithUser } from "../types/app-types.js";

type AdminManagementControllerDeps = {
    authorize: (req: RequestWithUser, res: express.Response, permission: Permission) => AdminContext | null;
    logAudit: (params: AuditParams) => Promise<void>;
    validateClassTeacherAssignments: (params: {
        schoolId: string;
        classIdToExclude?: string;
        teacherId?: string | null;
        assistantTeacherId?: string | null;
    }) => Promise<{ ok: true } | { ok: false; error: string }>;
};

export function createAdminManagementController(deps: AdminManagementControllerDeps) {
    const { authorize, logAudit, validateClassTeacherAssignments } = deps;
    const paramToString = (value: string | string[] | undefined) => (Array.isArray(value) ? value[0] : value);

    const updateStudent = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "students:write");
        if (!context) return;

        const studentId = paramToString(req.params.id);
        if (!studentId) { res.status(400).json({ error: "Student id is required" }); return; }
        const existing = await prisma.student.findUnique({ where: { id: studentId } });
        if (!existing) { res.status(404).json({ error: "Student not found" }); return; }
        if (context.schoolId && existing.schoolId !== context.schoolId) { res.status(403).json({ error: "Forbidden" }); return; }

        const updated = await prisma.student.update({
            where: { id: studentId },
            data: {
                ...(req.body.firstName ? { firstName: String(req.body.firstName) } : {}),
                ...(req.body.otherNames !== undefined ? { otherNames: req.body.otherNames || null } : {}),
                ...(req.body.lastName ? { lastName: String(req.body.lastName) } : {}),
                ...(req.body.gender !== undefined
                    ? {
                        gender:
                            req.body.gender === "MALE" || req.body.gender === "FEMALE"
                                ? req.body.gender
                                : null,
                    }
                    : {}),
                ...(req.body.email !== undefined ? { email: req.body.email || null } : {}),
                ...(req.body.dateOfBirth ? { dateOfBirth: new Date(req.body.dateOfBirth) } : {}),
                ...(req.body.previousSchool !== undefined ? { previousSchool: req.body.previousSchool || null } : {}),
                ...(req.body.picture !== undefined ? { picture: req.body.picture || null } : {}),
                ...(req.body.medicalCondition !== undefined ? { medicalCondition: req.body.medicalCondition || null } : {}),
                ...(req.body.allergies !== undefined ? { allergies: req.body.allergies || null } : {}),
                ...(req.body.guardianInfo !== undefined ? { guardianInfo: req.body.guardianInfo || null } : {}),
                ...(req.body.classId !== undefined ? { classId: req.body.classId || null } : {}),
            },
        });

        await logAudit({ req, action: "STUDENT_UPDATE", entityType: "Student", entityId: studentId, schoolId: context.schoolId, actorUserId: context.userId, actorRole: context.role, metadata: req.body });
        res.json(updated);
    };

    const deactivateStudent = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "students:write");
        if (!context) return;

        const studentId = paramToString(req.params.id);
        if (!studentId) { res.status(400).json({ error: "Student id is required" }); return; }
        const existing = await prisma.student.findUnique({ where: { id: studentId } });
        if (!existing) { res.status(404).json({ error: "Student not found" }); return; }
        if (context.schoolId && existing.schoolId !== context.schoolId) { res.status(403).json({ error: "Forbidden" }); return; }

        const updated = await prisma.student.update({ where: { id: studentId }, data: { status: "INACTIVE" } });
        await logAudit({ req, action: "STUDENT_DEACTIVATE", entityType: "Student", entityId: studentId, schoolId: context.schoolId, actorUserId: context.userId, actorRole: context.role });
        res.json(updated);
    };

    const activateStudent = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "students:write");
        if (!context) return;

        const studentId = paramToString(req.params.id);
        if (!studentId) { res.status(400).json({ error: "Student id is required" }); return; }
        const existing = await prisma.student.findUnique({ where: { id: studentId } });
        if (!existing) { res.status(404).json({ error: "Student not found" }); return; }
        if (context.schoolId && existing.schoolId !== context.schoolId) { res.status(403).json({ error: "Forbidden" }); return; }

        const updated = await prisma.student.update({ where: { id: studentId }, data: { status: "ACTIVE" } });
        await logAudit({ req, action: "STUDENT_ACTIVATE", entityType: "Student", entityId: studentId, schoolId: context.schoolId, actorUserId: context.userId, actorRole: context.role });
        res.json(updated);
    };

    const importStudents = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "students:write");
        if (!context) return;

        const schoolId = context.schoolId ?? req.body.schoolId;
        if (!schoolId) { res.status(400).json({ error: "Missing school scope" }); return; }

        const rows: Array<{
            firstName: string;
            otherNames?: string;
            lastName: string;
            gender?: "MALE" | "FEMALE";
            email?: string;
            dateOfBirth?: string;
            previousSchool?: string;
            medicalCondition?: string;
            allergies?: string;
            picture?: string;
            fatherFirstName?: string;
            fatherLastName?: string;
            fatherPhone?: string;
            fatherEmail?: string;
            fatherOccupation?: string;
            fatherResidentialAddress?: string;
            fatherPostalAddress?: string;
            motherFirstName?: string;
            motherLastName?: string;
            motherPhone?: string;
            motherEmail?: string;
            motherOccupation?: string;
            motherResidentialAddress?: string;
            motherPostalAddress?: string;
            classId?: string;
        }> = req.body.rows ?? [];
        if (!Array.isArray(rows) || rows.length === 0) { res.status(400).json({ error: "No rows provided" }); return; }

        const created = await prisma.$transaction(
            rows.filter(r => r.firstName && r.lastName).map(r =>
                prisma.student.create({
                    data: {
                        firstName: r.firstName,
                        otherNames: r.otherNames || null,
                        lastName: r.lastName,
                        gender: r.gender === "MALE" || r.gender === "FEMALE" ? r.gender : null,
                        email: r.email || null,
                        dateOfBirth: r.dateOfBirth ? new Date(r.dateOfBirth) : new Date("2000-01-01"),
                        previousSchool: r.previousSchool || null,
                        picture: r.picture || null,
                        medicalCondition: r.medicalCondition || null,
                        allergies: r.allergies || null,
                        guardianInfo: {
                            father: {
                                firstName: r.fatherFirstName,
                                lastName: r.fatherLastName,
                                phone: r.fatherPhone,
                                email: r.fatherEmail,
                                occupation: r.fatherOccupation,
                                residentialAddress: r.fatherResidentialAddress,
                                postalAddress: r.fatherPostalAddress,
                            },
                            mother: {
                                firstName: r.motherFirstName,
                                lastName: r.motherLastName,
                                phone: r.motherPhone,
                                email: r.motherEmail,
                                occupation: r.motherOccupation,
                                residentialAddress: r.motherResidentialAddress,
                                postalAddress: r.motherPostalAddress,
                            },
                        },
                        schoolId,
                        classId: r.classId || null,
                    },
                })
            )
        );

        await logAudit({ req, action: "STUDENT_IMPORT", entityType: "Student", schoolId, actorUserId: context.userId, actorRole: context.role, metadata: { count: created.length } });
        res.status(201).json({ imported: created.length, students: created });
    };

    const updateTeacher = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "teachers:write");
        if (!context) return;

        const teacherId = paramToString(req.params.id);
        if (!teacherId) { res.status(400).json({ error: "Teacher id is required" }); return; }
        const existing = await prisma.teacher.findUnique({ where: { id: teacherId } });
        if (!existing) { res.status(404).json({ error: "Teacher not found" }); return; }
        if (context.schoolId && existing.schoolId !== context.schoolId) { res.status(403).json({ error: "Forbidden" }); return; }

        const updated = await prisma.teacher.update({
            where: { id: teacherId },
            data: {
                ...(req.body.firstName ? { firstName: String(req.body.firstName) } : {}),
                ...(req.body.lastName ? { lastName: String(req.body.lastName) } : {}),
                ...(req.body.otherNames !== undefined ? { otherNames: req.body.otherNames || null } : {}),
                ...(req.body.dateOfBirth !== undefined ? { dateOfBirth: req.body.dateOfBirth ? new Date(String(req.body.dateOfBirth)) : null } : {}),
                ...(req.body.ssnitNumber !== undefined ? { ssnitNumber: req.body.ssnitNumber || null } : {}),
                ...(req.body.educationalLevel !== undefined ? { educationalLevel: req.body.educationalLevel || null } : {}),
                ...(req.body.certifications !== undefined ? { certifications: req.body.certifications || null } : {}),
                ...(req.body.picture !== undefined ? { picture: req.body.picture || null } : {}),
                ...(req.body.maritalStatus !== undefined ? { maritalStatus: req.body.maritalStatus || null } : {}),
                ...(req.body.nextOfKin !== undefined ? { nextOfKin: req.body.nextOfKin || null } : {}),
                ...(req.body.nextOfKinRelationship !== undefined ? { nextOfKinRelationship: req.body.nextOfKinRelationship || null } : {}),
                ...(req.body.residentialAddress !== undefined ? { residentialAddress: req.body.residentialAddress || null } : {}),
                ...(req.body.email ? { email: String(req.body.email) } : {}),
                ...(req.body.phone !== undefined ? { phone: req.body.phone || null } : {}),
                ...(req.body.subject !== undefined ? { subject: req.body.subject || null } : {}),
            },
        });

        await logAudit({ req, action: "TEACHER_UPDATE", entityType: "Teacher", entityId: teacherId, schoolId: context.schoolId, actorUserId: context.userId, actorRole: context.role, metadata: req.body });
        res.json(updated);
    };

    const deactivateTeacher = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "teachers:write");
        if (!context) return;

        const teacherId = paramToString(req.params.id);
        if (!teacherId) { res.status(400).json({ error: "Teacher id is required" }); return; }
        const existing = await prisma.teacher.findUnique({ where: { id: teacherId } });
        if (!existing) { res.status(404).json({ error: "Teacher not found" }); return; }
        if (context.schoolId && existing.schoolId !== context.schoolId) { res.status(403).json({ error: "Forbidden" }); return; }

        const updated = await prisma.teacher.update({ where: { id: teacherId }, data: { status: "INACTIVE" } });
        await logAudit({ req, action: "TEACHER_DEACTIVATE", entityType: "Teacher", entityId: teacherId, schoolId: context.schoolId, actorUserId: context.userId, actorRole: context.role });
        res.json(updated);
    };

    const activateTeacher = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "teachers:write");
        if (!context) return;

        const teacherId = paramToString(req.params.id);
        if (!teacherId) { res.status(400).json({ error: "Teacher id is required" }); return; }
        const existing = await prisma.teacher.findUnique({ where: { id: teacherId } });
        if (!existing) { res.status(404).json({ error: "Teacher not found" }); return; }
        if (context.schoolId && existing.schoolId !== context.schoolId) { res.status(403).json({ error: "Forbidden" }); return; }

        const updated = await prisma.teacher.update({ where: { id: teacherId }, data: { status: "ACTIVE" } });
        await logAudit({ req, action: "TEACHER_ACTIVATE", entityType: "Teacher", entityId: teacherId, schoolId: context.schoolId, actorUserId: context.userId, actorRole: context.role });
        res.json(updated);
    };

    const importTeachers = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "teachers:write");
        if (!context) return;

        const schoolId = context.schoolId ?? req.body.schoolId;
        if (!schoolId) { res.status(400).json({ error: "Missing school scope" }); return; }

        const rows: Array<{
            firstName?: string;
            lastName?: string;
            otherNames?: string;
            dateOfBirth?: string;
            ssnitNumber?: string;
            educationalLevel?: string;
            certifications?: string;
            picture?: string;
            maritalStatus?: string;
            nextOfKin?: string;
            nextOfKinRelationship?: string;
            residentialAddress?: string;
            email?: string;
            phone?: string;
            subject?: string;
        }> = req.body.rows ?? [];
        if (!Array.isArray(rows) || rows.length === 0) { res.status(400).json({ error: "No rows provided" }); return; }

        const defaultTeacherPasswordHash = await bcrypt.hash(process.env.DEFAULT_TEACHER_PASSWORD ?? "Teacher@123", 10);

        const created: Awaited<ReturnType<typeof prisma.teacher.create>>[] = [];
        const errors: { row: number; error: string }[] = [];

        for (let i = 0; i < rows.length; i++) {
            const r = rows[i]!;
            const validation = createTeacherSchema.safeParse({
                firstName: r.firstName ?? "",
                lastName: r.lastName ?? "",
                otherNames: r.otherNames ?? "",
                dateOfBirth: r.dateOfBirth ?? "",
                ssnitNumber: r.ssnitNumber ?? "",
                educationalLevel: r.educationalLevel ?? "",
                certifications: r.certifications ?? "",
                picture: r.picture ?? "",
                maritalStatus: r.maritalStatus ?? "",
                nextOfKin: r.nextOfKin ?? "",
                nextOfKinRelationship: r.nextOfKinRelationship ?? "",
                residentialAddress: r.residentialAddress ?? "",
                email: r.email ?? "",
                phone: r.phone ?? "",
                subject: r.subject ?? "",
                schoolId,
            });

            if (!validation.success) {
                errors.push({
                    row: i + 2,
                    error: validation.error.issues.map((issue) => issue.message).join("; "),
                });
                continue;
            }

            try {
                const t = await prisma.teacher.create({
                    data: {
                        firstName: validation.data.firstName,
                        lastName: validation.data.lastName,
                        otherNames: validation.data.otherNames || null,
                        dateOfBirth: new Date(validation.data.dateOfBirth),
                        ssnitNumber: validation.data.ssnitNumber,
                        educationalLevel: validation.data.educationalLevel,
                        certifications: validation.data.certifications || null,
                        picture: validation.data.picture || null,
                        maritalStatus: validation.data.maritalStatus,
                        nextOfKin: validation.data.nextOfKin,
                        nextOfKinRelationship: validation.data.nextOfKinRelationship,
                        residentialAddress: validation.data.residentialAddress,
                        email: validation.data.email,
                        passwordHash: defaultTeacherPasswordHash,
                        phone: validation.data.phone,
                        subject: validation.data.subject || null,
                        schoolId,
                    },
                });
                created.push(t);
            } catch {
                errors.push({ row: i + 2, error: `Duplicate email: ${validation.data.email}` });
            }
        }

        await logAudit({ req, action: "TEACHER_IMPORT", entityType: "Teacher", schoolId, actorUserId: context.userId, actorRole: context.role, metadata: { count: created.length, errors: errors.length } });
        res.status(201).json({ imported: created.length, teachers: created, errors });
    };

    const updateClass = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "classes:write");
        if (!context) return;

        const classId = paramToString(req.params.id);
        if (!classId) { res.status(400).json({ error: "Class id is required" }); return; }
        const existing = await prisma.class.findUnique({ where: { id: classId } });
        if (!existing) { res.status(404).json({ error: "Class not found" }); return; }
        if (context.schoolId && existing.schoolId !== context.schoolId) { res.status(403).json({ error: "Forbidden" }); return; }

        const nextTeacherId = req.body.teacherId !== undefined ? (req.body.teacherId || null) : existing.teacherId;
        const nextAssistantTeacherId = req.body.assistantTeacherId !== undefined ? (req.body.assistantTeacherId || null) : existing.assistantTeacherId;

        const teacherAssignmentValidation = await validateClassTeacherAssignments({
            schoolId: existing.schoolId,
            classIdToExclude: classId,
            teacherId: nextTeacherId,
            assistantTeacherId: nextAssistantTeacherId,
        });
        if (!teacherAssignmentValidation.ok) {
            res.status(400).json({ error: teacherAssignmentValidation.error });
            return;
        }

        const updated = await prisma.class.update({
            where: { id: classId },
            data: {
                ...(req.body.name ? { name: String(req.body.name) } : {}),
                ...(req.body.grade ? { grade: String(req.body.grade) } : {}),
                ...(req.body.section !== undefined ? { section: req.body.section || null } : {}),
                ...(req.body.academicYear ? { academicYear: String(req.body.academicYear) } : {}),
                ...(req.body.feeAmount !== undefined ? { feeAmount: req.body.feeAmount === null || req.body.feeAmount === "" ? null : Number(req.body.feeAmount) } : {}),
                ...(req.body.teacherId !== undefined ? { teacherId: req.body.teacherId || null } : {}),
                ...(req.body.assistantTeacherId !== undefined ? { assistantTeacherId: req.body.assistantTeacherId || null } : {}),
                ...(req.body.prefectStudentId !== undefined ? { prefectStudentId: req.body.prefectStudentId || null } : {}),
                ...(req.body.assistantPrefectStudentId !== undefined ? { assistantPrefectStudentId: req.body.assistantPrefectStudentId || null } : {}),
            },
        });

        await logAudit({ req, action: "CLASS_UPDATE", entityType: "Class", entityId: classId, schoolId: context.schoolId, actorUserId: context.userId, actorRole: context.role, metadata: req.body });
        res.json(updated);
    };

    const updateSubject = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "subjects:write");
        if (!context) return;

        const subjectId = paramToString(req.params.id);
        if (!subjectId) { res.status(400).json({ error: "Subject id is required" }); return; }
        const existing = await prisma.subject.findUnique({ where: { id: subjectId } });
        if (!existing) { res.status(404).json({ error: "Subject not found" }); return; }
        if (context.schoolId && existing.schoolId !== context.schoolId) { res.status(403).json({ error: "Forbidden" }); return; }

        const updated = await prisma.subject.update({
            where: { id: subjectId },
            data: {
                ...(req.body.name ? { name: String(req.body.name) } : {}),
                ...(req.body.code ? { code: String(req.body.code) } : {}),
                ...(req.body.groupName !== undefined ? { groupName: req.body.groupName || null } : {}),
                ...(req.body.description !== undefined ? { description: req.body.description || null } : {}),
            },
        });

        await logAudit({ req, action: "SUBJECT_UPDATE", entityType: "Subject", entityId: subjectId, schoolId: context.schoolId, actorUserId: context.userId, actorRole: context.role, metadata: req.body });
        res.json(updated);
    };

    const deleteSubject = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "subjects:write");
        if (!context) return;

        const subjectId = paramToString(req.params.id);
        if (!subjectId) { res.status(400).json({ error: "Subject id is required" }); return; }
        const existing = await prisma.subject.findUnique({ where: { id: subjectId } });
        if (!existing) { res.status(404).json({ error: "Subject not found" }); return; }
        if (context.schoolId && existing.schoolId !== context.schoolId) { res.status(403).json({ error: "Forbidden" }); return; }

        await prisma.subject.delete({ where: { id: subjectId } });
        await logAudit({ req, action: "SUBJECT_DELETE", entityType: "Subject", entityId: subjectId, schoolId: context.schoolId, actorUserId: context.userId, actorRole: context.role });
        res.json({ ok: true });
    };

    const getSettings = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "reports:read");
        if (!context) return;

        const schoolId = context.schoolId;
        if (!schoolId) { res.status(400).json({ error: "No school scope" }); return; }

        let settings = await prisma.schoolSettings.findUnique({ where: { schoolId } });
        if (!settings) {
            try {
                settings = await prisma.schoolSettings.create({
                    data: { schoolId, academicYear: "2025-2026" },
                });
            } catch (error) {
                const isUniqueSchoolSettingsConflict =
                    error instanceof Prisma.PrismaClientKnownRequestError
                    && error.code === "P2002";
                if (!isUniqueSchoolSettingsConflict) {
                    throw error;
                }

                settings = await prisma.schoolSettings.findUnique({ where: { schoolId } });
                if (!settings) {
                    throw error;
                }
            }
        }

        const school = await prisma.school.findUnique({
            where: { id: schoolId },
            select: { logo: true },
        });

        res.json({
            ...settings,
            logo: school?.logo ?? null,
        });
    };

    const updateSettings = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "settings:write");
        if (!context) return;

        const schoolId = context.schoolId;
        if (!schoolId) { res.status(400).json({ error: "No school scope" }); return; }

        const updateData = {
            ...(req.body.academicYear !== undefined ? { academicYear: String(req.body.academicYear) } : {}),
            ...(req.body.gradingConfig !== undefined ? { gradingConfig: req.body.gradingConfig } : {}),
            ...(req.body.feeCategories !== undefined ? { feeCategories: req.body.feeCategories } : {}),
        };

        let updated = await prisma.schoolSettings.findUnique({ where: { schoolId } });
        if (updated) {
            updated = await prisma.schoolSettings.update({
                where: { schoolId },
                data: updateData,
            });
        } else {
            try {
                updated = await prisma.schoolSettings.create({
                    data: {
                        schoolId,
                        academicYear: req.body.academicYear ?? "2025-2026",
                        gradingConfig: req.body.gradingConfig ?? null,
                        feeCategories: req.body.feeCategories ?? null,
                    },
                });
            } catch (error) {
                const isUniqueSchoolSettingsConflict =
                    error instanceof Prisma.PrismaClientKnownRequestError
                    && error.code === "P2002";
                if (!isUniqueSchoolSettingsConflict) {
                    throw error;
                }

                updated = await prisma.schoolSettings.update({
                    where: { schoolId },
                    data: updateData,
                });
            }
        }

        if (req.body.logo !== undefined) {
            await prisma.school.update({
                where: { id: schoolId },
                data: {
                    logo: req.body.logo ? String(req.body.logo) : null,
                },
            });
        }

        const school = await prisma.school.findUnique({
            where: { id: schoolId },
            select: { logo: true },
        });

        await logAudit({ req, action: "SETTINGS_UPDATE", entityType: "SchoolSettings", entityId: updated.id, schoolId, actorUserId: context.userId, actorRole: context.role, metadata: { academicYear: updated.academicYear } });
        res.json({
            ...updated,
            logo: school?.logo ?? null,
        });
    };

    return {
        updateStudent,
        deactivateStudent,
        activateStudent,
        importStudents,
        updateTeacher,
        deactivateTeacher,
        activateTeacher,
        importTeachers,
        updateClass,
        updateSubject,
        deleteSubject,
        getSettings,
        updateSettings,
    };
}
