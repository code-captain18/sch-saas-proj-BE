import type express from "express";
import { createAdminManagementController } from "../controllers/admin-management-controller.js";
import type { AdminContext, AuditParams, Permission, RequestWithUser } from "../types/app-types.js";

type AdminManagementDeps = {
    authorize: (req: RequestWithUser, res: express.Response, permission: Permission) => AdminContext | null;
    logAudit: (params: AuditParams) => Promise<void>;
    validateClassTeacherAssignments: (params: {
        schoolId: string;
        classIdToExclude?: string;
        teacherId?: string | null;
        assistantTeacherId?: string | null;
    }) => Promise<{ ok: true } | { ok: false; error: string }>;
};

export function registerAdminManagementRoutes(app: express.Express, deps: AdminManagementDeps) {
    const controller = createAdminManagementController(deps);

    app.patch("/api/admin/students/:id", controller.updateStudent);
    app.patch("/api/admin/students/:id/deactivate", controller.deactivateStudent);
    app.patch("/api/admin/students/:id/activate", controller.activateStudent);
    app.post("/api/admin/students/import", controller.importStudents);

    app.patch("/api/admin/teachers/:id", controller.updateTeacher);
    app.patch("/api/admin/teachers/:id/deactivate", controller.deactivateTeacher);
    app.patch("/api/admin/teachers/:id/activate", controller.activateTeacher);
    app.post("/api/admin/teachers/import", controller.importTeachers);

    app.patch("/api/admin/classes/:id", controller.updateClass);
    app.patch("/api/admin/subjects/:id", controller.updateSubject);
    app.delete("/api/admin/subjects/:id", controller.deleteSubject);

    app.get("/api/admin/settings", controller.getSettings);
    app.patch("/api/admin/settings", controller.updateSettings);
}
