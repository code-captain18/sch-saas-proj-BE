import type express from "express";
import { createAdminAcademicController } from "../controllers/admin-academic-controller.js";
import { validateBody } from "../lib/middleware.js";
import { createClassSchema, createSubjectSchema } from "../lib/validations.js";
import type { AdminContext, AuditParams, Permission, RequestWithUser } from "../types/app-types.js";

type AdminAcademicRouteDeps = {
    authorize: (req: RequestWithUser, res: express.Response, permission: Permission) => AdminContext | null;
    logAudit: (params: AuditParams) => Promise<void>;
    validateClassTeacherAssignments: (params: {
        schoolId: string;
        classIdToExclude?: string;
        teacherId?: string | null;
        assistantTeacherId?: string | null;
    }) => Promise<{ ok: true } | { ok: false; error: string }>;
};

export function registerAdminAcademicRoutes(app: express.Express, deps: AdminAcademicRouteDeps) {
    const controller = createAdminAcademicController(deps);

    app.get("/api/admin/classes", controller.listClasses);
    app.post("/api/admin/classes", validateBody(createClassSchema), controller.createClass);

    app.get("/api/admin/subjects", controller.listSubjects);
    app.post("/api/admin/subjects", validateBody(createSubjectSchema), controller.createSubject);

    app.post("/api/admin/classes/:classId/subjects", controller.linkClassSubject);
    app.post("/api/admin/subjects/bulk-assign", controller.bulkAssignSubjects);

    app.get("/api/admin/teaching-assignments", controller.listTeachingAssignments);
    app.post("/api/admin/teaching-assignments", controller.createTeachingAssignment);
    app.delete("/api/admin/teaching-assignments/:id", controller.deleteTeachingAssignment);
}
