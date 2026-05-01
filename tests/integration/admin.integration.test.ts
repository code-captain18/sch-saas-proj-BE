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


test("GET /api/admin/schools without bearer token returns 401", async () => {
    const response = await request(app)
        .get("/api/admin/schools")
        .expect(401);

    assert.equal(response.body.error, "Unauthorized: missing bearer token");
});



test("GET /api/admin/schools with invalid bearer token returns 401", async () => {
    const response = await request(app)
        .get("/api/admin/schools")
        .set("authorization", "Bearer invalid-token")
        .expect(401);

    assert.equal(response.body.error, "Unauthorized: invalid or expired token");
});



test("GET /api/admin/schools returns schools for SUPER_ADMIN with valid token", async () => {
    const originalFindMany = prisma.school.findMany;
    const mockedSchools = [
        { id: "school_1", name: "Accra Model", district: "Accra" },
        { id: "school_2", name: "Kumasi Prep", district: "Kumasi" },
    ];

    (prisma.school.findMany as unknown as (...args: unknown[]) => Promise<unknown>) = async () => mockedSchools;

    try {
        const token = createAccessToken({
            sub: "admin_super_1",
            role: "SUPER_ADMIN",
            schoolId: null,
            userType: "ADMIN_USER",
        });

        const response = await request(app)
            .get("/api/admin/schools")
            .set("authorization", `Bearer ${token}`)
            .expect(200);

        assert.ok(Array.isArray(response.body));
        assert.equal(response.body.length, 2);
        assert.equal(response.body[0].name, "Accra Model");
    } finally {
        prisma.school.findMany = originalFindMany;
    }
});



test("GET /api/admin/schools forbids SCHOOL_ADMIN token with missing school scope", async () => {
    const token = createAccessToken({
        sub: "admin_school_1",
        role: "SCHOOL_ADMIN",
        schoolId: null,
        userType: "ADMIN_USER",
    });

    const response = await request(app)
        .get("/api/admin/schools")
        .set("authorization", `Bearer ${token}`)
        .expect(403);

    assert.equal(response.body.error, "Forbidden: missing school scope for this user");
});



test("POST /api/admin/schools creates a school for SUPER_ADMIN", async () => {
    const createdSchool = {
        id: "school_new_1",
        name: "Tamale Science Academy",
        district: "Tamale",
        address: "North Ridge",
        phone: "0244000000",
        email: "admin@tamaleacademy.edu.gh",
    };

    const restoreSchoolCreate = stubPrismaMethod(
        prisma.school,
        "create",
        (async () => createdSchool) as typeof prisma.school.create,
    );
    const restoreAdminUserFindUnique = stubPrismaMethod(
        prisma.adminUser,
        "findUnique",
        (async () => ({ id: "admin_super_1" })) as typeof prisma.adminUser.findUnique,
    );
    const restoreAuditLogCreate = stubPrismaMethod(
        prisma.auditLog,
        "create",
        (async () => ({ id: "audit_1" })) as typeof prisma.auditLog.create,
    );

    try {
        const token = createAccessToken({
            sub: "admin_super_1",
            role: "SUPER_ADMIN",
            schoolId: null,
            userType: "ADMIN_USER",
        });

        const response = await request(app)
            .post("/api/admin/schools")
            .set("authorization", `Bearer ${token}`)
            .send({
                name: "Tamale Science Academy",
                district: "Tamale",
                address: "North Ridge",
                phone: "0244000000",
                email: "admin@tamaleacademy.edu.gh",
            })
            .expect(201);

        assert.equal(response.body.id, "school_new_1");
        assert.equal(response.body.name, "Tamale Science Academy");
    } finally {
        restoreSchoolCreate();
        restoreAdminUserFindUnique();
        restoreAuditLogCreate();
    }
});



test("PATCH /api/admin/schools/:id returns 404 when school does not exist", async () => {
    const restoreSchoolFindUnique = stubPrismaMethod(
        prisma.school,
        "findUnique",
        (async () => null) as typeof prisma.school.findUnique,
    );

    try {
        const token = createAccessToken({
            sub: "admin_super_1",
            role: "SUPER_ADMIN",
            schoolId: null,
            userType: "ADMIN_USER",
        });

        const response = await request(app)
            .patch("/api/admin/schools/nonexistent")
            .set("authorization", `Bearer ${token}`)
            .send({ name: "Updated Name" })
            .expect(404);

        assert.equal(response.body.error, "School not found");
    } finally {
        restoreSchoolFindUnique();
    }
});



test("PATCH /api/admin/schools/:id updates school for SUPER_ADMIN", async () => {
    const updatedSchool = {
        id: "school_1",
        name: "Updated Accra Model",
        district: "Accra Metro",
        address: "Airport Residential",
        phone: "0244111111",
        email: "hello@updated-accra.edu.gh",
    };

    const restoreSchoolFindUnique = stubPrismaMethod(
        prisma.school,
        "findUnique",
        (async () => ({ id: "school_1", name: "Old School" })) as typeof prisma.school.findUnique,
    );
    const restoreSchoolUpdate = stubPrismaMethod(
        prisma.school,
        "update",
        (async () => updatedSchool) as typeof prisma.school.update,
    );
    const restoreAdminUserFindUnique = stubPrismaMethod(
        prisma.adminUser,
        "findUnique",
        (async () => ({ id: "admin_super_1" })) as typeof prisma.adminUser.findUnique,
    );
    const restoreAuditLogCreate = stubPrismaMethod(
        prisma.auditLog,
        "create",
        (async () => ({ id: "audit_patch_1" })) as typeof prisma.auditLog.create,
    );

    try {
        const token = createAccessToken({
            sub: "admin_super_1",
            role: "SUPER_ADMIN",
            schoolId: null,
            userType: "ADMIN_USER",
        });

        const response = await request(app)
            .patch("/api/admin/schools/school_1")
            .set("authorization", `Bearer ${token}`)
            .send({
                name: "Updated Accra Model",
                district: "Accra Metro",
                address: "Airport Residential",
                phone: "0244111111",
                email: "hello@updated-accra.edu.gh",
            })
            .expect(200);

        assert.equal(response.body.id, "school_1");
        assert.equal(response.body.name, "Updated Accra Model");
        assert.equal(response.body.district, "Accra Metro");
    } finally {
        restoreSchoolFindUnique();
        restoreSchoolUpdate();
        restoreAdminUserFindUnique();
        restoreAuditLogCreate();
    }
});



test("POST /api/admin/students creates student for SCHOOL_ADMIN within school scope", async () => {
    const createdStudent = {
        id: "student_1",
        firstName: "Ama",
        otherNames: null,
        lastName: "Mensah",
        gender: "FEMALE",
        email: "ama@example.com",
        dateOfBirth: new Date("2014-04-01"),
        previousSchool: null,
        picture: null,
        medicalCondition: null,
        allergies: null,
        guardianInfo: {
            father: { firstName: "Kwame", phone: "0244000001" },
        },
        schoolId: "school_1",
        classId: "class_1",
    };

    const restoreStudentCreate = stubPrismaMethod(
        prisma.student,
        "create",
        (async () => createdStudent) as typeof prisma.student.create,
    );
    const restoreAdminUserFindUnique = stubPrismaMethod(
        prisma.adminUser,
        "findUnique",
        (async () => ({ id: "admin_school_1" })) as typeof prisma.adminUser.findUnique,
    );
    const restoreAuditLogCreate = stubPrismaMethod(
        prisma.auditLog,
        "create",
        (async () => ({ id: "audit_student_create_1" })) as typeof prisma.auditLog.create,
    );

    try {
        const token = createAccessToken({
            sub: "admin_school_1",
            role: "SCHOOL_ADMIN",
            schoolId: "school_1",
            userType: "ADMIN_USER",
        });

        const response = await request(app)
            .post("/api/admin/students")
            .set("authorization", `Bearer ${token}`)
            .send({
                firstName: "Ama",
                otherNames: "",
                lastName: "Mensah",
                gender: "FEMALE",
                email: "ama@example.com",
                dateOfBirth: "2014-04-01",
                previousSchool: "",
                picture: "",
                medicalCondition: "",
                allergies: "",
                fatherFirstName: "Kwame",
                fatherLastName: "Mensah",
                fatherPhone: "0244000001",
                fatherEmail: "",
                fatherOccupation: "",
                fatherResidentialAddress: "",
                fatherPostalAddress: "",
                motherFirstName: "",
                motherLastName: "",
                motherPhone: "",
                motherEmail: "",
                motherOccupation: "",
                motherResidentialAddress: "",
                motherPostalAddress: "",
                motherAddressSameAsFather: "false",
                classId: "class_1",
                schoolId: "school_1",
            })
            .expect(201);

        assert.equal(response.body.id, "student_1");
        assert.equal(response.body.schoolId, "school_1");
        assert.equal(response.body.firstName, "Ama");
    } finally {
        restoreStudentCreate();
        restoreAdminUserFindUnique();
        restoreAuditLogCreate();
    }
});



test("PATCH /api/admin/students/:id updates student when found", async () => {
    const restoreStudentFindUnique = stubPrismaMethod(
        prisma.student,
        "findUnique",
        (async () => ({ id: "student_1", schoolId: "school_1" })) as typeof prisma.student.findUnique,
    );
    const restoreStudentUpdate = stubPrismaMethod(
        prisma.student,
        "update",
        (async () => ({ id: "student_1", firstName: "Ama Updated", schoolId: "school_1" })) as typeof prisma.student.update,
    );
    const restoreAdminUserFindUnique = stubPrismaMethod(
        prisma.adminUser,
        "findUnique",
        (async () => ({ id: "admin_school_1" })) as typeof prisma.adminUser.findUnique,
    );
    const restoreAuditLogCreate = stubPrismaMethod(
        prisma.auditLog,
        "create",
        (async () => ({ id: "audit_student_patch_1" })) as typeof prisma.auditLog.create,
    );

    try {
        const token = createAccessToken({
            sub: "admin_school_1",
            role: "SCHOOL_ADMIN",
            schoolId: "school_1",
            userType: "ADMIN_USER",
        });

        const response = await request(app)
            .patch("/api/admin/students/student_1")
            .set("authorization", `Bearer ${token}`)
            .send({ firstName: "Ama Updated" })
            .expect(200);

        assert.equal(response.body.id, "student_1");
        assert.equal(response.body.firstName, "Ama Updated");
    } finally {
        restoreStudentFindUnique();
        restoreStudentUpdate();
        restoreAdminUserFindUnique();
        restoreAuditLogCreate();
    }
});



test("POST /api/admin/teachers creates teacher with default password hash", async () => {
    const restoreTeacherCreate = stubPrismaMethod(
        prisma.teacher,
        "create",
        (async () => ({
            id: "teacher_1",
            firstName: "Kojo",
            lastName: "Owusu",
            email: "kojo@example.com",
            schoolId: "school_1",
            status: "ACTIVE",
        })) as typeof prisma.teacher.create,
    );
    const restoreAdminUserFindUnique = stubPrismaMethod(
        prisma.adminUser,
        "findUnique",
        (async () => ({ id: "admin_school_1" })) as typeof prisma.adminUser.findUnique,
    );
    const restoreAuditLogCreate = stubPrismaMethod(
        prisma.auditLog,
        "create",
        (async () => ({ id: "audit_teacher_create_1" })) as typeof prisma.auditLog.create,
    );

    try {
        const token = createAccessToken({
            sub: "admin_school_1",
            role: "SCHOOL_ADMIN",
            schoolId: "school_1",
            userType: "ADMIN_USER",
        });

        const response = await request(app)
            .post("/api/admin/teachers")
            .set("authorization", `Bearer ${token}`)
            .send({
                firstName: "Kojo",
                lastName: "Owusu",
                otherNames: "",
                dateOfBirth: "1990-03-11",
                ssnitNumber: "SSN-0001234",
                educationalLevel: "B.Ed",
                certifications: "",
                picture: "",
                maritalStatus: "Single",
                nextOfKin: "Akua Owusu",
                nextOfKinRelationship: "Sister",
                residentialAddress: "Madina, Accra",
                email: "kojo@example.com",
                phone: "0244000002",
                subject: "Mathematics",
                schoolId: "school_1",
            })
            .expect(201);

        assert.equal(response.body.id, "teacher_1");
        assert.equal(response.body.firstName, "Kojo");
        assert.equal(response.body.schoolId, "school_1");
    } finally {
        restoreTeacherCreate();
        restoreAdminUserFindUnique();
        restoreAuditLogCreate();
    }
});



test("PATCH /api/admin/teachers/:id/deactivate sets teacher status to INACTIVE", async () => {
    const restoreTeacherFindUnique = stubPrismaMethod(
        prisma.teacher,
        "findUnique",
        (async () => ({ id: "teacher_1", schoolId: "school_1" })) as typeof prisma.teacher.findUnique,
    );
    const restoreTeacherUpdate = stubPrismaMethod(
        prisma.teacher,
        "update",
        (async () => ({ id: "teacher_1", status: "INACTIVE" })) as typeof prisma.teacher.update,
    );
    const restoreAdminUserFindUnique = stubPrismaMethod(
        prisma.adminUser,
        "findUnique",
        (async () => ({ id: "admin_school_1" })) as typeof prisma.adminUser.findUnique,
    );
    const restoreAuditLogCreate = stubPrismaMethod(
        prisma.auditLog,
        "create",
        (async () => ({ id: "audit_teacher_deactivate_1" })) as typeof prisma.auditLog.create,
    );

    try {
        const token = createAccessToken({
            sub: "admin_school_1",
            role: "SCHOOL_ADMIN",
            schoolId: "school_1",
            userType: "ADMIN_USER",
        });

        const response = await request(app)
            .patch("/api/admin/teachers/teacher_1/deactivate")
            .set("authorization", `Bearer ${token}`)
            .expect(200);

        assert.equal(response.body.id, "teacher_1");
        assert.equal(response.body.status, "INACTIVE");
    } finally {
        restoreTeacherFindUnique();
        restoreTeacherUpdate();
        restoreAdminUserFindUnique();
        restoreAuditLogCreate();
    }
});



test("POST /api/admin/students returns 403 for SCHOOL_ADMIN with missing school scope", async () => {
    const token = createAccessToken({
        sub: "admin_school_1",
        role: "SCHOOL_ADMIN",
        schoolId: null,
        userType: "ADMIN_USER",
    });

    const response = await request(app)
        .post("/api/admin/students")
        .set("authorization", `Bearer ${token}`)
        .send({
            firstName: "Ama",
            otherNames: "",
            lastName: "Mensah",
            gender: "FEMALE",
            email: "ama@example.com",
            dateOfBirth: "2014-04-01",
            previousSchool: "",
            picture: "",
            medicalCondition: "",
            allergies: "",
            fatherFirstName: "",
            fatherLastName: "",
            fatherPhone: "",
            fatherEmail: "",
            fatherOccupation: "",
            fatherResidentialAddress: "",
            fatherPostalAddress: "",
            motherFirstName: "",
            motherLastName: "",
            motherPhone: "",
            motherEmail: "",
            motherOccupation: "",
            motherResidentialAddress: "",
            motherPostalAddress: "",
            motherAddressSameAsFather: "false",
            classId: "class_1",
            schoolId: "school_1",
        })
        .expect(403);

    assert.equal(response.body.error, "Forbidden: missing school scope for this user");
});



test("PATCH /api/admin/students/:id returns 404 when student does not exist", async () => {
    const restoreStudentFindUnique = stubPrismaMethod(
        prisma.student,
        "findUnique",
        (async () => null) as typeof prisma.student.findUnique,
    );

    try {
        const token = createAccessToken({
            sub: "admin_school_1",
            role: "SCHOOL_ADMIN",
            schoolId: "school_1",
            userType: "ADMIN_USER",
        });

        const response = await request(app)
            .patch("/api/admin/students/missing_student")
            .set("authorization", `Bearer ${token}`)
            .send({ firstName: "No One" })
            .expect(404);

        assert.equal(response.body.error, "Student not found");
    } finally {
        restoreStudentFindUnique();
    }
});



test("POST /api/admin/teachers rejects malformed payload with 400", async () => {
    const token = createAccessToken({
        sub: "admin_school_1",
        role: "SCHOOL_ADMIN",
        schoolId: "school_1",
        userType: "ADMIN_USER",
    });

    const response = await request(app)
        .post("/api/admin/teachers")
        .set("authorization", `Bearer ${token}`)
        .send({ email: "bad-email" })
        .expect(400);

    assert.equal(response.body.error, "Validation failed");
    assert.ok(Array.isArray(response.body.details));
});



test("PATCH /api/admin/teachers/:id/deactivate returns 404 when teacher does not exist", async () => {
    const restoreTeacherFindUnique = stubPrismaMethod(
        prisma.teacher,
        "findUnique",
        (async () => null) as typeof prisma.teacher.findUnique,
    );

    try {
        const token = createAccessToken({
            sub: "admin_school_1",
            role: "SCHOOL_ADMIN",
            schoolId: "school_1",
            userType: "ADMIN_USER",
        });

        const response = await request(app)
            .patch("/api/admin/teachers/missing_teacher/deactivate")
            .set("authorization", `Bearer ${token}`)
            .expect(404);

        assert.equal(response.body.error, "Teacher not found");
    } finally {
        restoreTeacherFindUnique();
    }
});



test("POST /api/admin/schools returns 403 for VIEWER role", async () => {
    const token = createAccessToken({
        sub: "viewer_1",
        role: "VIEWER",
        schoolId: "school_1",
        userType: "ADMIN_USER",
    });

    const response = await request(app)
        .post("/api/admin/schools")
        .set("authorization", `Bearer ${token}`)
        .send({
            name: "Blocked School",
            district: "Accra",
            address: "Somewhere",
            phone: "0244555555",
            email: "blocked@example.com",
        })
        .expect(403);

    assert.equal(response.body.error, "Forbidden: insufficient role permissions");
});



test("PATCH /api/admin/students/:id returns 403 for cross-school resource", async () => {
    const restoreStudentFindUnique = stubPrismaMethod(
        prisma.student,
        "findUnique",
        (async () => ({ id: "student_cross", schoolId: "school_2" })) as typeof prisma.student.findUnique,
    );

    try {
        const token = createAccessToken({
            sub: "admin_school_1",
            role: "SCHOOL_ADMIN",
            schoolId: "school_1",
            userType: "ADMIN_USER",
        });

        const response = await request(app)
            .patch("/api/admin/students/student_cross")
            .set("authorization", `Bearer ${token}`)
            .send({ firstName: "Should Fail" })
            .expect(403);

        assert.equal(response.body.error, "Forbidden");
    } finally {
        restoreStudentFindUnique();
    }
});



test("PATCH /api/admin/teachers/:id returns 403 for cross-school resource", async () => {
    const restoreTeacherFindUnique = stubPrismaMethod(
        prisma.teacher,
        "findUnique",
        (async () => ({ id: "teacher_cross", schoolId: "school_2" })) as typeof prisma.teacher.findUnique,
    );

    try {
        const token = createAccessToken({
            sub: "admin_school_1",
            role: "SCHOOL_ADMIN",
            schoolId: "school_1",
            userType: "ADMIN_USER",
        });

        const response = await request(app)
            .patch("/api/admin/teachers/teacher_cross")
            .set("authorization", `Bearer ${token}`)
            .send({ firstName: "Should Fail" })
            .expect(403);

        assert.equal(response.body.error, "Forbidden");
    } finally {
        restoreTeacherFindUnique();
    }
});


