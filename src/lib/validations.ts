import { z } from "zod";

// Auth schemas
export const loginSchema = z.object({
    email: z.string().email("Invalid email address"),
    password: z.string().min(6, "Password must be at least 6 characters"),
});

export const refreshTokenSchema = z.object({
    refreshToken: z.string().min(1, "Refresh token is required"),
});

// School schemas
export const createSchoolSchema = z.object({
    name: z.string().min(1, "School name is required").max(150),
    district: z.string().min(1, "District is required").max(150),
    address: z.string().max(255).optional(),
    phone: z.string().max(50).optional(),
    email: z.string().email("Invalid email address").optional().or(z.literal("")),
});

export const updateSchoolSchema = z.object({
    name: z.string().min(1, "School name is required").max(150).optional(),
    district: z.string().min(1, "District is required").max(150).optional(),
    address: z.string().max(255).optional(),
    phone: z.string().max(50).optional(),
    email: z.string().email("Invalid email address").optional().or(z.literal("")),
});

// Student schemas
export const createStudentSchema = z.object({
    firstName: z.string().min(1, "First name is required").max(100),
    otherNames: z.string().max(100).optional().or(z.literal("")),
    lastName: z.string().min(1, "Last name is required").max(100),
    gender: z.enum(["MALE", "FEMALE"], { message: "Gender is required" }),
    email: z.string().email("Invalid email address").optional().or(z.literal("")),
    dateOfBirth: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "Date must be in YYYY-MM-DD format"),
    previousSchool: z.string().max(255).optional().or(z.literal("")),
    picture: z.string().optional().or(z.literal("")),
    medicalCondition: z.string().max(500).optional().or(z.literal("")),
    allergies: z.string().max(500).optional().or(z.literal("")),
    fatherFirstName: z.string().max(100).optional().or(z.literal("")),
    fatherLastName: z.string().max(100).optional().or(z.literal("")),
    fatherPhone: z.string().max(20).optional().or(z.literal("")),
    fatherEmail: z.string().email("Invalid email").optional().or(z.literal("")),
    fatherOccupation: z.string().max(100).optional().or(z.literal("")),
    fatherResidentialAddress: z.string().max(255).optional().or(z.literal("")),
    fatherPostalAddress: z.string().max(255).optional().or(z.literal("")),
    motherFirstName: z.string().max(100).optional().or(z.literal("")),
    motherLastName: z.string().max(100).optional().or(z.literal("")),
    motherPhone: z.string().max(20).optional().or(z.literal("")),
    motherEmail: z.string().email("Invalid email").optional().or(z.literal("")),
    motherOccupation: z.string().max(100).optional().or(z.literal("")),
    motherResidentialAddress: z.string().max(255).optional().or(z.literal("")),
    motherPostalAddress: z.string().max(255).optional().or(z.literal("")),
    motherAddressSameAsFather: z.string().optional(),
    classId: z.string().optional(),
    schoolId: z.string().min(1, "School ID is required"),
});

// Teacher schemas
export const createTeacherSchema = z.object({
    firstName: z.string().min(1, "First name is required").max(100),
    lastName: z.string().min(1, "Last name is required").max(100),
    otherNames: z.string().max(100).optional().or(z.literal("")),
    dateOfBirth: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "Date of birth must be in YYYY-MM-DD format"),
    ssnitNumber: z.string().min(1, "SSNIT number is required").max(50),
    educationalLevel: z.string().min(1, "Educational level is required").max(100),
    certifications: z.string().max(500).optional().or(z.literal("")),
    picture: z.string().max(500).optional().or(z.literal("")),
    maritalStatus: z.string().min(1, "Marital status is required").max(50),
    nextOfKin: z.string().min(1, "Next of kin is required").max(100),
    nextOfKinRelationship: z.string().min(1, "Relationship with next of kin is required").max(100),
    residentialAddress: z.string().min(1, "Residential address is required").max(255),
    email: z.string().email("Invalid email address"),
    phone: z.string().min(1, "Phone is required").max(20),
    subject: z.string().optional(),
    role: z.enum(["PRINCIPAL", "ACCOUNTANT", "STAFF", "VIEWER"]).optional(),
    schoolId: z.string().min(1, "School ID is required"),
});

// Class schemas
export const createClassSchema = z.object({
    name: z.string().min(1, "Class name is required").max(100),
    grade: z.string().min(1, "Grade is required").max(50),
    section: z.string().optional(),
    academicYear: z.string().regex(/^\d{4}-\d{4}$/, "Academic year must be in YYYY-YYYY format"),
    feeAmount: z.coerce.number().min(0, "Fee amount cannot be negative").optional(),
    teacherId: z.string().optional(),
    assistantTeacherId: z.string().optional(),
    schoolId: z.string().min(1, "School ID is required"),
});

// Subject schemas
export const createSubjectSchema = z.object({
    name: z.string().min(1, "Subject name is required").max(100),
    code: z.string().min(1, "Subject code is required").max(20),
    groupName: z.string().max(100).optional(),
    description: z.string().optional(),
    schoolId: z.string().min(1, "School ID is required"),
});

const feeLineItemSchema = z.object({
    label: z.string().min(1, "Fee item label is required").max(100),
    amount: z.coerce.number().positive("Fee item amount must be positive"),
});

export const createFeeStructureSchema = z.object({
    title: z.string().min(1, "Template title is required").max(150),
    academicYear: z.string().regex(/^\d{4}-\d{4}$/, "Academic year must be in YYYY-YYYY format"),
    term: z.enum(["TERM_1", "TERM_2", "TERM_3"]),
    scopeType: z.enum(["CLASS", "GRADE"]),
    classId: z.string().optional(),
    grade: z.string().optional(),
    items: z.array(feeLineItemSchema).min(1, "At least one fee item is required"),
    schoolId: z.string().min(1, "School ID is required"),
}).superRefine((value, ctx) => {
    if (value.scopeType === "CLASS" && !value.classId) {
        ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ["classId"],
            message: "Class is required when scope type is CLASS",
        });
    }

    if (value.scopeType === "GRADE" && !value.grade) {
        ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ["grade"],
            message: "Grade is required when scope type is GRADE",
        });
    }
});

// Fee Invoice schemas
export const createFeeInvoiceSchema = z.object({
    studentId: z.string().min(1, "Student ID is required"),
    amount: z.coerce.number().positive("Amount must be positive").optional(),
    term: z.enum(["TERM_1", "TERM_2", "TERM_3"]),
    academicYear: z.string().regex(/^\d{4}-\d{4}$/, "Academic year must be in YYYY-YYYY format"),
    dueDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "Date must be in YYYY-MM-DD format"),
    description: z.string().optional(),
    lineItems: z.array(feeLineItemSchema).optional(),
    feeStructureId: z.string().optional(),
    schoolId: z.string().min(1, "School ID is required"),
}).superRefine((value, ctx) => {
    if (!value.amount && (!value.lineItems || value.lineItems.length === 0)) {
        ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ["amount"],
            message: "Provide an amount or at least one fee item",
        });
    }
});

export const generateFeeInvoicesSchema = z.object({
    feeStructureId: z.string().min(1, "Fee structure is required"),
    dueDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "Date must be in YYYY-MM-DD format"),
    description: z.string().optional(),
});

// Query parameter schemas
export const auditLogsQuerySchema = z.object({
    action: z.string().optional(),
    status: z.enum(["SUCCESS", "FAILED"]).optional(),
    from: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "Date must be in YYYY-MM-DD format").optional(),
    to: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "Date must be in YYYY-MM-DD format").optional(),
    limit: z.number().int().positive().max(1000).optional(),
    format: z.enum(["json", "csv"]).optional(),
});

export const attendanceQuerySchema = z.object({
    classId: z.string().min(1).optional(),
    from: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "Date must be in YYYY-MM-DD format").optional(),
    to: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "Date must be in YYYY-MM-DD format").optional(),
});

// Type exports
export type LoginInput = z.infer<typeof loginSchema>;
export type RefreshTokenInput = z.infer<typeof refreshTokenSchema>;
export type CreateSchoolInput = z.infer<typeof createSchoolSchema>;
export type UpdateSchoolInput = z.infer<typeof updateSchoolSchema>;
export type CreateStudentInput = z.infer<typeof createStudentSchema>;
export type CreateTeacherInput = z.infer<typeof createTeacherSchema>;
export type CreateClassInput = z.infer<typeof createClassSchema>;
export type CreateSubjectInput = z.infer<typeof createSubjectSchema>;
export type CreateFeeStructureInput = z.infer<typeof createFeeStructureSchema>;
export type CreateFeeInvoiceInput = z.infer<typeof createFeeInvoiceSchema>;
export type GenerateFeeInvoicesInput = z.infer<typeof generateFeeInvoicesSchema>;
export type AuditLogsQuery = z.infer<typeof auditLogsQuerySchema>;
export type AttendanceQuery = z.infer<typeof attendanceQuerySchema>;
