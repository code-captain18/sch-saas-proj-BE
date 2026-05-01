import bcrypt from "bcryptjs";
import type express from "express";
import { Prisma } from "@prisma/client";
import prisma from "../lib/prisma.js";
import { getGuardianPhones, sendSms } from "../lib/sms.js";
import { addMonths, getSchoolSubscriptionStatus, resolveTrialEndsAt } from "../lib/subscription.js";
import type { AdminContext, AuditParams, Permission, RequestWithUser } from "../types/app-types.js";

type AdminCoreControllerDeps = {
    authorize: (req: RequestWithUser, res: express.Response, permission: Permission) => AdminContext | null;
    logAudit: (params: AuditParams) => Promise<void>;
};

export function createAdminCoreController(deps: AdminCoreControllerDeps) {
    const { authorize, logAudit } = deps;

    const toSchoolResponse = (school: {
        id: string;
        name: string;
        district: string;
        isActive: boolean;
        subscriptionStartedAt: Date;
        subscriptionTrialEndsAt: Date | null;
        subscriptionPaidUntil: Date | null;
        subscriptionMonthlyFee: Prisma.Decimal;
        address: string | null;
        phone: string | null;
        email: string | null;
        logo: string | null;
        totalStudents: number;
        activeTeachers: number;
    }) => {
        const status = getSchoolSubscriptionStatus({
            isActive: school.isActive,
            createdAt: school.subscriptionStartedAt,
            subscriptionStartedAt: school.subscriptionStartedAt,
            subscriptionTrialEndsAt: school.subscriptionTrialEndsAt,
            subscriptionPaidUntil: school.subscriptionPaidUntil,
        });

        return {
            ...school,
            subscriptionMonthlyFee: Number(school.subscriptionMonthlyFee),
            subscriptionStatus: status,
            subscriptionTrialEndsAt: resolveTrialEndsAt({
                subscriptionStartedAt: school.subscriptionStartedAt,
                subscriptionTrialEndsAt: school.subscriptionTrialEndsAt,
            }),
        };
    };

    const listSchools = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "schools:read");
        if (!context) return;

        const schools = await prisma.school.findMany({
            where: context.role === "SUPER_ADMIN" ? undefined : { id: context.schoolId ?? "" },
            orderBy: { name: "asc" },
        });

        res.json(schools.map((school) => toSchoolResponse(school)));
    };

    const createSchool = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "schools:write");
        if (!context) return;

        const school = await prisma.school.create({
            data: {
                name: req.body.name,
                district: req.body.district,
                address: req.body.address,
                phone: req.body.phone,
                email: req.body.email,
                subscriptionStartedAt: new Date(),
                subscriptionTrialEndsAt: addMonths(new Date(), 4),
                subscriptionMonthlyFee: req.body.subscriptionMonthlyFee ?? 0,
            },
        });

        await logAudit({
            req,
            action: "SCHOOL_CREATE",
            entityType: "School",
            entityId: school.id,
            schoolId: school.id,
            actorUserId: context.userId,
            actorRole: context.role,
            metadata: { name: school.name, district: school.district },
        });

        res.status(201).json(toSchoolResponse(school));
    };

    const updateSchool = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "schools:write");
        if (!context) return;

        const schoolIdParam = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
        if (!schoolIdParam) {
            res.status(400).json({ error: "school id is required" });
            return;
        }

        const existing = await prisma.school.findUnique({ where: { id: schoolIdParam } });
        if (!existing) {
            res.status(404).json({ error: "School not found" });
            return;
        }

        const school = await prisma.school.update({
            where: { id: schoolIdParam },
            data: {
                name: req.body.name,
                district: req.body.district,
                address: req.body.address,
                phone: req.body.phone,
                email: req.body.email,
                subscriptionMonthlyFee: req.body.subscriptionMonthlyFee,
            },
        });

        await logAudit({
            req,
            action: "SCHOOL_UPDATE",
            entityType: "School",
            entityId: school.id,
            schoolId: school.id,
            actorUserId: context.userId,
            actorRole: context.role,
            metadata: {
                name: school.name,
                district: school.district,
                address: school.address,
                phone: school.phone,
                email: school.email,
                subscriptionMonthlyFee: Number(school.subscriptionMonthlyFee),
            },
        });

        res.json(toSchoolResponse(school));
    };

    const deactivateSchool = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "schools:write");
        if (!context) return;

        const schoolIdParam = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
        if (!schoolIdParam) {
            res.status(400).json({ error: "school id is required" });
            return;
        }

        const existing = await prisma.school.findUnique({ where: { id: schoolIdParam } });
        if (!existing) {
            res.status(404).json({ error: "School not found" });
            return;
        }

        const school = await prisma.school.update({
            where: { id: schoolIdParam },
            data: { isActive: false },
        });

        await logAudit({
            req,
            action: "SCHOOL_DEACTIVATE",
            entityType: "School",
            entityId: school.id,
            schoolId: school.id,
            actorUserId: context.userId,
            actorRole: context.role,
            metadata: { name: school.name, district: school.district },
        });

        res.json(toSchoolResponse(school));
    };

    const activateSchool = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "schools:write");
        if (!context) return;

        const schoolIdParam = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
        if (!schoolIdParam) {
            res.status(400).json({ error: "school id is required" });
            return;
        }

        const existing = await prisma.school.findUnique({ where: { id: schoolIdParam } });
        if (!existing) {
            res.status(404).json({ error: "School not found" });
            return;
        }

        const school = await prisma.school.update({
            where: { id: schoolIdParam },
            data: { isActive: true },
        });

        await logAudit({
            req,
            action: "SCHOOL_ACTIVATE",
            entityType: "School",
            entityId: school.id,
            schoolId: school.id,
            actorUserId: context.userId,
            actorRole: context.role,
            metadata: { name: school.name, district: school.district },
        });

        res.json(toSchoolResponse(school));
    };

    const recordSchoolSubscriptionPayment = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "schools:write");
        if (!context) return;

        const schoolIdParam = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
        if (!schoolIdParam) {
            res.status(400).json({ error: "school id is required" });
            return;
        }

        const existing = await prisma.school.findUnique({ where: { id: schoolIdParam } });
        if (!existing) {
            res.status(404).json({ error: "School not found" });
            return;
        }

        const months = Number(req.body.months ?? 1);
        const now = new Date();
        const trialEndsAt = resolveTrialEndsAt({
            subscriptionStartedAt: existing.subscriptionStartedAt,
            subscriptionTrialEndsAt: existing.subscriptionTrialEndsAt,
        });
        const baseDate = existing.subscriptionPaidUntil && existing.subscriptionPaidUntil > now
            ? existing.subscriptionPaidUntil
            : (now > trialEndsAt ? now : trialEndsAt);
        const newPaidUntil = addMonths(baseDate, months);

        const school = await prisma.school.update({
            where: { id: schoolIdParam },
            data: {
                subscriptionPaidUntil: newPaidUntil,
            },
        });

        await logAudit({
            req,
            action: "SCHOOL_SUBSCRIPTION_PAYMENT",
            entityType: "School",
            entityId: school.id,
            schoolId: school.id,
            actorUserId: context.userId,
            actorRole: context.role,
            metadata: {
                months,
                paidUntil: newPaidUntil.toISOString(),
            },
        });

        res.json(toSchoolResponse(school));
    };

    const deleteSchool = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "schools:write");
        if (!context) return;

        const schoolIdParam = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
        if (!schoolIdParam) {
            res.status(400).json({ error: "school id is required" });
            return;
        }

        const existing = await prisma.school.findUnique({ where: { id: schoolIdParam } });
        if (!existing) {
            res.status(404).json({ error: "School not found" });
            return;
        }

        await prisma.school.delete({ where: { id: schoolIdParam } });

        await logAudit({
            req,
            action: "SCHOOL_DELETE",
            entityType: "School",
            entityId: existing.id,
            schoolId: existing.id,
            actorUserId: context.userId,
            actorRole: context.role,
            metadata: { name: existing.name, district: existing.district },
        });

        res.json({ ok: true });
    };

    const listStudents = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "students:read");
        if (!context) return;

        const where = context.schoolId ? { schoolId: context.schoolId } : undefined;
        const students = await prisma.student.findMany({
            where,
            include: { class: true },
            orderBy: { createdAt: "desc" },
        });
        res.json(students);
    };

    const createStudent = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "students:write");
        if (!context) return;

        const schoolId = context.schoolId ?? req.body.schoolId;
        if (!schoolId) {
            res.status(400).json({ error: "schoolId is required" });
            return;
        }

        const guardianInfo: Record<string, unknown> = {};
        const fatherData = {
            firstName: req.body.fatherFirstName,
            lastName: req.body.fatherLastName,
            phone: req.body.fatherPhone,
            email: req.body.fatherEmail,
            occupation: req.body.fatherOccupation,
            residentialAddress: req.body.fatherResidentialAddress,
            postalAddress: req.body.fatherPostalAddress,
        };

        if (fatherData.firstName || fatherData.lastName) {
            guardianInfo.father = Object.fromEntries(Object.entries(fatherData).filter(([, value]) => value));
        }

        const motherAddressSameAsFather = req.body.motherAddressSameAsFather === "true";
        const motherData = {
            firstName: req.body.motherFirstName,
            lastName: req.body.motherLastName,
            phone: req.body.motherPhone,
            email: req.body.motherEmail,
            occupation: req.body.motherOccupation,
            residentialAddress: motherAddressSameAsFather ? req.body.fatherResidentialAddress : req.body.motherResidentialAddress,
            postalAddress: motherAddressSameAsFather ? req.body.fatherPostalAddress : req.body.motherPostalAddress,
        };

        if (motherData.firstName || motherData.lastName) {
            guardianInfo.mother = Object.fromEntries(Object.entries(motherData).filter(([, value]) => value));
        }

        const student = await prisma.student.create({
            data: {
                firstName: req.body.firstName,
                otherNames: req.body.otherNames,
                lastName: req.body.lastName,
                gender: req.body.gender,
                email: req.body.email,
                dateOfBirth: new Date(req.body.dateOfBirth),
                previousSchool: req.body.previousSchool,
                picture: req.body.picture,
                medicalCondition: req.body.medicalCondition,
                allergies: req.body.allergies,
                guardianInfo: Object.keys(guardianInfo).length > 0 ? (guardianInfo as Prisma.InputJsonValue) : Prisma.JsonNull,
                schoolId,
                classId: req.body.classId,
            },
        });

        await logAudit({
            req,
            action: "STUDENT_CREATE",
            entityType: "Student",
            entityId: student.id,
            schoolId,
            actorUserId: context.userId,
            actorRole: context.role,
            metadata: { firstName: student.firstName, lastName: student.lastName, gender: req.body.gender },
        });

        const guardianPhones = getGuardianPhones(student.guardianInfo);
        const studentName = [student.firstName, student.lastName].filter(Boolean).join(" ");
        for (const phone of guardianPhones) {
            sendSms(phone, `Dear Guardian, ${studentName} has been successfully enrolled at your school on SchoolFlow. Contact the school for further details.`);
        }

        res.status(201).json(student);
    };

    const listTeachers = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "teachers:read");
        if (!context) return;

        const where = context.schoolId ? { schoolId: context.schoolId } : undefined;
        const teachers = await prisma.teacher.findMany({ where, orderBy: { createdAt: "desc" } });
        res.json(teachers);
    };

    const createTeacher = async (req: RequestWithUser, res: express.Response) => {
        const context = authorize(req, res, "teachers:write");
        if (!context) return;

        const schoolId = context.schoolId ?? req.body.schoolId;
        if (!schoolId) {
            res.status(400).json({ error: "schoolId is required" });
            return;
        }

        const defaultTeacherPasswordHash = await bcrypt.hash(process.env.DEFAULT_TEACHER_PASSWORD ?? "Teacher@123", 10);

        const teacher = await prisma.teacher.create({
            data: {
                firstName: req.body.firstName,
                lastName: req.body.lastName,
                otherNames: req.body.otherNames || null,
                dateOfBirth: req.body.dateOfBirth ? new Date(req.body.dateOfBirth) : null,
                ssnitNumber: req.body.ssnitNumber,
                educationalLevel: req.body.educationalLevel,
                certifications: req.body.certifications || null,
                picture: req.body.picture || null,
                maritalStatus: req.body.maritalStatus,
                nextOfKin: req.body.nextOfKin,
                nextOfKinRelationship: req.body.nextOfKinRelationship,
                residentialAddress: req.body.residentialAddress,
                email: req.body.email,
                passwordHash: defaultTeacherPasswordHash,
                phone: req.body.phone,
                subject: req.body.subject,
                schoolId,
            },
        });

        await logAudit({
            req,
            action: "TEACHER_CREATE",
            entityType: "Teacher",
            entityId: teacher.id,
            schoolId,
            actorUserId: context.userId,
            actorRole: context.role,
            metadata: { firstName: teacher.firstName, lastName: teacher.lastName },
        });
        res.status(201).json(teacher);
    };

    return {
        listSchools,
        createSchool,
        updateSchool,
        deactivateSchool,
        activateSchool,
        recordSchoolSubscriptionPayment,
        deleteSchool,
        listStudents,
        createStudent,
        listTeachers,
        createTeacher,
    };
}
