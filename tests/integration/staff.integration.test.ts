import assert from "node:assert/strict";
import crypto from "node:crypto";
import test, { after } from "node:test";
import request from "supertest";

import { app } from "../../src/index.js";
import { shutdownOtpSecurity } from "../../src/lib/otp-security.js";
import prisma from "../../src/lib/prisma.js";
import { createAccessToken, stubPrismaMethod } from "./test-helpers.js";

after(async () => {
    await shutdownOtpSecurity();
});


test("POST /api/staff/attendance marks today's attendance", async () => {
    const today = new Date().toISOString().split("T")[0];

    const restoreStudentFindFirst = stubPrismaMethod(
        prisma.student,
        "findFirst",
        (async () => ({ id: "student_1", firstName: "Ama", lastName: "Mensah", guardianInfo: null })) as typeof prisma.student.findFirst,
    );
    const restoreAttendanceUpsert = stubPrismaMethod(
        prisma.attendance,
        "upsert",
        (async () => ({
            id: "attendance_1",
            studentId: "student_1",
            classId: "class_1",
            schoolId: "school_1",
            status: "PRESENT",
        })) as typeof prisma.attendance.upsert,
    );
    const restoreAdminUserFindUnique = stubPrismaMethod(
        prisma.adminUser,
        "findUnique",
        (async () => ({ id: "admin_school_1" })) as typeof prisma.adminUser.findUnique,
    );
    const restoreAuditLogCreate = stubPrismaMethod(
        prisma.auditLog,
        "create",
        (async () => ({ id: "audit_attendance_1" })) as typeof prisma.auditLog.create,
    );

    try {
        const token = createAccessToken({
            sub: "admin_school_1",
            role: "SCHOOL_ADMIN",
            schoolId: "school_1",
            userType: "ADMIN_USER",
        });

        const response = await request(app)
            .post("/api/staff/attendance")
            .set("authorization", `Bearer ${token}`)
            .send({
                studentId: "student_1",
                classId: "class_1",
                date: today,
                status: "PRESENT",
                remarks: "On time",
            })
            .expect(201);

        assert.equal(response.body.id, "attendance_1");
        assert.equal(response.body.status, "PRESENT");
    } finally {
        restoreStudentFindFirst();
        restoreAttendanceUpsert();
        restoreAdminUserFindUnique();
        restoreAuditLogCreate();
    }
});



test("POST /api/staff/scores creates score for valid class-subject assignment", async () => {
    const restoreStudentFindFirst = stubPrismaMethod(
        prisma.student,
        "findFirst",
        (async () => ({ id: "student_1" })) as typeof prisma.student.findFirst,
    );
    const restoreClassSubjectFindFirst = stubPrismaMethod(
        prisma.classSubject,
        "findFirst",
        (async () => ({ id: "class_subject_1", subject: { name: "Mathematics", code: "MATH" } })) as typeof prisma.classSubject.findFirst,
    );
    const restoreScoreCreate = stubPrismaMethod(
        prisma.score,
        "create",
        (async () => ({
            id: "score_1",
            studentId: "student_1",
            classId: "class_1",
            subjectId: "subject_1",
            schoolId: "school_1",
            score: 78,
            maxScore: 100,
            term: "TERM_1",
            academicYear: "2025-2026",
        })) as typeof prisma.score.create,
    );
    const restoreAdminUserFindUnique = stubPrismaMethod(
        prisma.adminUser,
        "findUnique",
        (async () => ({ id: "admin_school_1" })) as typeof prisma.adminUser.findUnique,
    );
    const restoreAuditLogCreate = stubPrismaMethod(
        prisma.auditLog,
        "create",
        (async () => ({ id: "audit_score_1" })) as typeof prisma.auditLog.create,
    );

    try {
        const token = createAccessToken({
            sub: "admin_school_1",
            role: "SCHOOL_ADMIN",
            schoolId: "school_1",
            userType: "ADMIN_USER",
        });

        const response = await request(app)
            .post("/api/staff/scores")
            .set("authorization", `Bearer ${token}`)
            .send({
                studentId: "student_1",
                classId: "class_1",
                subjectId: "subject_1",
                score: 78,
                maxScore: 100,
                term: "TERM_1",
                academicYear: "2025-2026",
                remarks: "Good work",
            })
            .expect(201);

        assert.equal(response.body.id, "score_1");
        assert.equal(response.body.score, 78);
        assert.equal(response.body.term, "TERM_1");
    } finally {
        restoreStudentFindFirst();
        restoreClassSubjectFindFirst();
        restoreScoreCreate();
        restoreAdminUserFindUnique();
        restoreAuditLogCreate();
    }
});



test("POST /api/staff/attendance rejects date that is not today", async () => {
    const token = createAccessToken({
        sub: "admin_school_1",
        role: "SCHOOL_ADMIN",
        schoolId: "school_1",
        userType: "ADMIN_USER",
    });

    const response = await request(app)
        .post("/api/staff/attendance")
        .set("authorization", `Bearer ${token}`)
        .send({
            studentId: "student_1",
            classId: "class_1",
            date: "2020-01-01",
            status: "PRESENT",
        })
        .expect(400);

    assert.equal(response.body.error, "Attendance can only be marked for today");
});



test("POST /api/staff/scores rejects payload with missing required fields", async () => {
    const token = createAccessToken({
        sub: "admin_school_1",
        role: "SCHOOL_ADMIN",
        schoolId: "school_1",
        userType: "ADMIN_USER",
    });

    const response = await request(app)
        .post("/api/staff/scores")
        .set("authorization", `Bearer ${token}`)
        .send({ studentId: "student_1" })
        .expect(400);

    assert.equal(response.body.error, "Missing required fields");
});



test("POST /api/staff/attendance returns 403 for VIEWER role", async () => {
    const token = createAccessToken({
        sub: "viewer_1",
        role: "VIEWER",
        schoolId: "school_1",
        userType: "ADMIN_USER",
    });

    const today = new Date().toISOString().split("T")[0];
    const response = await request(app)
        .post("/api/staff/attendance")
        .set("authorization", `Bearer ${token}`)
        .send({
            studentId: "student_1",
            classId: "class_1",
            date: today,
            status: "PRESENT",
        })
        .expect(403);

    assert.equal(response.body.error, "Forbidden: insufficient role permissions");
});



test("POST /api/staff/scores returns 403 for VIEWER role", async () => {
    const token = createAccessToken({
        sub: "viewer_1",
        role: "VIEWER",
        schoolId: "school_1",
        userType: "ADMIN_USER",
    });

    const response = await request(app)
        .post("/api/staff/scores")
        .set("authorization", `Bearer ${token}`)
        .send({
            studentId: "student_1",
            classId: "class_1",
            subjectId: "subject_1",
            score: 85,
            term: "TERM_1",
            academicYear: "2025-2026",
        })
        .expect(403);

    assert.equal(response.body.error, "Forbidden: insufficient role permissions");
});



test("POST /api/staff/scores returns 409 on duplicate score unique constraint", async () => {
    const restoreStudentFindFirst = stubPrismaMethod(
        prisma.student,
        "findFirst",
        (async () => ({ id: "student_1" })) as typeof prisma.student.findFirst,
    );
    const restoreClassSubjectFindFirst = stubPrismaMethod(
        prisma.classSubject,
        "findFirst",
        (async () => ({ id: "class_subject_1", subject: { name: "Mathematics", code: "MATH" } })) as typeof prisma.classSubject.findFirst,
    );
    const restoreScoreCreate = stubPrismaMethod(
        prisma.score,
        "create",
        (async () => {
            throw Object.assign(new Error("Unique constraint failed"), {
                code: "P2002",
                clientVersion: "test",
            });
        }) as typeof prisma.score.create,
    );

    try {
        const token = createAccessToken({
            sub: "admin_school_1",
            role: "SCHOOL_ADMIN",
            schoolId: "school_1",
            userType: "ADMIN_USER",
        });

        const response = await request(app)
            .post("/api/staff/scores")
            .set("authorization", `Bearer ${token}`)
            .send({
                studentId: "student_1",
                classId: "class_1",
                subjectId: "subject_1",
                score: 78,
                maxScore: 100,
                term: "TERM_1",
                academicYear: "2025-2026",
            })
            .expect(409);

        assert.equal(response.body.error, "Score already exists for this student, subject, term, and academic year");
    } finally {
        restoreStudentFindFirst();
        restoreClassSubjectFindFirst();
        restoreScoreCreate();
    }
});


