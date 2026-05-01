import type { RequestWithUser } from "../types/app-types.js";
import prisma from "./prisma.js";

export async function getTeacherRestriction(req: RequestWithUser, schoolId: string | null) {
    if (req.authUser?.userType !== "TEACHER") {
        return null;
    }

    const teacher = await prisma.teacher.findUnique({
        where: { id: req.authUser.userId },
        select: {
            id: true,
            schoolId: true,
            subject: true,
        },
    });

    if (!teacher) {
        return {
            teacherId: req.authUser.userId,
            schoolId,
            allowedClassIds: [] as string[],
            taughtSubject: null as string | null,
            teachingAssignments: [] as Array<{ classId: string; subjectId: string }>,
        };
    }

    const assignedClasses = await prisma.class.findMany({
        where: {
            schoolId: schoolId ?? teacher.schoolId,
            OR: [{ teacherId: teacher.id }, { assistantTeacherId: teacher.id }],
        },
        select: { id: true },
    });

    const teachingAssignments = await prisma.teachingAssignment.findMany({
        where: {
            schoolId: schoolId ?? teacher.schoolId,
            teacherId: teacher.id,
        },
        select: {
            classId: true,
            subjectId: true,
        },
    });

    const explicitClassIds = teachingAssignments.map((item) => item.classId);
    const classIdSet = new Set<string>([...assignedClasses.map((item) => item.id), ...explicitClassIds]);

    return {
        teacherId: teacher.id,
        schoolId: schoolId ?? teacher.schoolId,
        allowedClassIds: [...classIdSet],
        taughtSubject: teacher.subject?.trim() || null,
        teachingAssignments,
    };
}

export function hasTeacherSubjectAccess(taughtSubject: string | null, subject: { name: string; code: string }) {
    if (!taughtSubject) return true;
    const normalized = taughtSubject.toLowerCase();
    return subject.name.toLowerCase() === normalized || subject.code.toLowerCase() === normalized;
}

export function hasExplicitTeachingAssignment(
    assignments: Array<{ classId: string; subjectId: string }>,
    classId: string,
    subjectId: string,
) {
    return assignments.some((item) => item.classId === classId && item.subjectId === subjectId);
}

export async function validateClassTeacherAssignments(params: {
    schoolId: string;
    classIdToExclude?: string;
    teacherId?: string | null;
    assistantTeacherId?: string | null;
}) {
    const teacherId = params.teacherId?.trim() || null;
    const assistantTeacherId = params.assistantTeacherId?.trim() || null;

    if (teacherId && assistantTeacherId && teacherId === assistantTeacherId) {
        return { ok: false as const, error: "Class teacher and assistant teacher cannot be the same person" };
    }

    const selectedTeacherIds = [teacherId, assistantTeacherId].filter(Boolean) as string[];
    if (selectedTeacherIds.length === 0) {
        return { ok: true as const };
    }

    const teachersInSchool = await prisma.teacher.findMany({
        where: {
            id: { in: selectedTeacherIds },
            schoolId: params.schoolId,
        },
        select: { id: true },
    });

    if (teachersInSchool.length !== selectedTeacherIds.length) {
        return { ok: false as const, error: "Selected teacher must belong to this school" };
    }

    const conflictingClass = await prisma.class.findFirst({
        where: {
            schoolId: params.schoolId,
            ...(params.classIdToExclude ? { id: { not: params.classIdToExclude } } : {}),
            OR: [
                ...(teacherId ? [{ teacherId }, { assistantTeacherId: teacherId }] : []),
                ...(assistantTeacherId ? [{ teacherId: assistantTeacherId }, { assistantTeacherId }] : []),
            ],
        },
        select: {
            id: true,
            name: true,
            teacherId: true,
            assistantTeacherId: true,
        },
    });

    if (conflictingClass) {
        return {
            ok: false as const,
            error: `Selected teacher is already assigned to class ${conflictingClass.name}`,
        };
    }

    return { ok: true as const };
}
