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
    lastName: z.string().min(1, "Last name is required").max(100),
    email: z.string().email("Invalid email address").optional().or(z.literal("")),
    dateOfBirth: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "Date must be in YYYY-MM-DD format"),
    classId: z.string().optional(),
    schoolId: z.string().min(1, "School ID is required"),
});

// Teacher schemas
export const createTeacherSchema = z.object({
    firstName: z.string().min(1, "First name is required").max(100),
    lastName: z.string().min(1, "Last name is required").max(100),
    email: z.string().email("Invalid email address"),
    phone: z.string().optional(),
    subject: z.string().optional(),
    schoolId: z.string().min(1, "School ID is required"),
});

// Class schemas
export const createClassSchema = z.object({
    name: z.string().min(1, "Class name is required").max(100),
    grade: z.string().min(1, "Grade is required").max(50),
    section: z.string().optional(),
    academicYear: z.string().regex(/^\d{4}-\d{4}$/, "Academic year must be in YYYY-YYYY format"),
    teacherId: z.string().optional(),
    schoolId: z.string().min(1, "School ID is required"),
});

// Subject schemas
export const createSubjectSchema = z.object({
    name: z.string().min(1, "Subject name is required").max(100),
    code: z.string().min(1, "Subject code is required").max(20),
    description: z.string().optional(),
    schoolId: z.string().min(1, "School ID is required"),
});

// Fee Invoice schemas
export const createFeeInvoiceSchema = z.object({
    studentId: z.string().min(1, "Student ID is required"),
    amount: z.number().positive("Amount must be positive"),
    dueDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "Date must be in YYYY-MM-DD format"),
    description: z.string().optional(),
    schoolId: z.string().min(1, "School ID is required"),
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

// Type exports
export type LoginInput = z.infer<typeof loginSchema>;
export type RefreshTokenInput = z.infer<typeof refreshTokenSchema>;
export type CreateSchoolInput = z.infer<typeof createSchoolSchema>;
export type UpdateSchoolInput = z.infer<typeof updateSchoolSchema>;
export type CreateStudentInput = z.infer<typeof createStudentSchema>;
export type CreateTeacherInput = z.infer<typeof createTeacherSchema>;
export type CreateClassInput = z.infer<typeof createClassSchema>;
export type CreateSubjectInput = z.infer<typeof createSubjectSchema>;
export type CreateFeeInvoiceInput = z.infer<typeof createFeeInvoiceSchema>;
export type AuditLogsQuery = z.infer<typeof auditLogsQuerySchema>;
