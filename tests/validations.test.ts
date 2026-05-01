import assert from "node:assert/strict";
import test from "node:test";

import {
    createFeeInvoiceSchema,
    createFeeStructureSchema,
    createStudentSchema,
    createTeacherSchema,
    loginSchema,
} from "../src/lib/validations.js";

test("loginSchema rejects invalid email", () => {
    const result = loginSchema.safeParse({ email: "bad-email", password: "123456" });
    assert.equal(result.success, false);
    if (!result.success) {
        assert.ok(result.error.issues.some((issue) => issue.message.includes("Invalid email")));
    }
});

test("createStudentSchema accepts a valid payload", () => {
    const result = createStudentSchema.safeParse({
        firstName: "Ama",
        otherNames: "",
        lastName: "Owusu",
        gender: "FEMALE",
        email: "",
        dateOfBirth: "2012-04-10",
        previousSchool: "",
        picture: "",
        medicalCondition: "",
        allergies: "",
        fatherFirstName: "Kwame",
        fatherLastName: "Owusu",
        fatherPhone: "0244000001",
        fatherEmail: "",
        fatherOccupation: "Trader",
        fatherResidentialAddress: "Accra",
        fatherPostalAddress: "",
        motherFirstName: "Akos",
        motherLastName: "Owusu",
        motherPhone: "0244000002",
        motherEmail: "",
        motherOccupation: "Nurse",
        motherResidentialAddress: "Accra",
        motherPostalAddress: "",
        motherAddressSameAsFather: "true",
        classId: "class_123",
        schoolId: "school_123",
    });

    assert.equal(result.success, true);
});

test("createTeacherSchema rejects when required fields are missing", () => {
    const result = createTeacherSchema.safeParse({
        firstName: "Kofi",
        lastName: "Mensah",
        dateOfBirth: "1988-01-20",
        email: "kofi@example.com",
        phone: "0244000099",
        schoolId: "school_123",
    });

    assert.equal(result.success, false);
    if (!result.success) {
        const issuePaths = result.error.issues.map((issue) => issue.path.join("."));
        assert.ok(issuePaths.includes("ssnitNumber"));
        assert.ok(issuePaths.includes("educationalLevel"));
    }
});

test("createFeeStructureSchema enforces classId when scopeType is CLASS", () => {
    const result = createFeeStructureSchema.safeParse({
        title: "JHS 1 Term 1",
        academicYear: "2025-2026",
        term: "TERM_1",
        scopeType: "CLASS",
        grade: "JHS 1",
        items: [{ label: "Tuition", amount: 500 }],
        schoolId: "school_123",
    });

    assert.equal(result.success, false);
    if (!result.success) {
        assert.ok(result.error.issues.some((issue) => issue.message.includes("Class is required")));
    }
});

test("createFeeStructureSchema enforces grade when scopeType is GRADE", () => {
    const result = createFeeStructureSchema.safeParse({
        title: "JHS All Term 2",
        academicYear: "2025-2026",
        term: "TERM_2",
        scopeType: "GRADE",
        classId: "class_123",
        items: [{ label: "PTA", amount: 100 }],
        schoolId: "school_123",
    });

    assert.equal(result.success, false);
    if (!result.success) {
        assert.ok(result.error.issues.some((issue) => issue.message.includes("Grade is required")));
    }
});

test("createFeeInvoiceSchema requires amount or line items", () => {
    const result = createFeeInvoiceSchema.safeParse({
        studentId: "student_1",
        term: "TERM_1",
        academicYear: "2025-2026",
        dueDate: "2026-05-30",
        schoolId: "school_1",
    });

    assert.equal(result.success, false);
    if (!result.success) {
        assert.ok(result.error.issues.some((issue) => issue.message.includes("Provide an amount")));
    }
});

test("createFeeInvoiceSchema accepts amount-only invoices", () => {
    const result = createFeeInvoiceSchema.safeParse({
        studentId: "student_1",
        amount: 1200,
        term: "TERM_1",
        academicYear: "2025-2026",
        dueDate: "2026-05-30",
        schoolId: "school_1",
    });

    assert.equal(result.success, true);
});
