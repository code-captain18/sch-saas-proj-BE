import type express from "express";
import { createAdminCoreController } from "../controllers/admin-core-controller.js";
import { validateBody } from "../lib/middleware.js";
import {
    createSchoolSchema,
    schoolSubscriptionPaymentSchema,
    createStudentSchema,
    createTeacherSchema,
    updateSchoolSchema,
} from "../lib/validations.js";
import type { AdminContext, AuditParams, Permission, RequestWithUser } from "../types/app-types.js";

type AdminCoreRouteDeps = {
    authorize: (req: RequestWithUser, res: express.Response, permission: Permission) => AdminContext | null;
    logAudit: (params: AuditParams) => Promise<void>;
};

export function registerAdminCoreRoutes(app: express.Express, deps: AdminCoreRouteDeps) {
    const controller = createAdminCoreController(deps);

    app.get("/api/admin/schools", controller.listSchools);
    app.post("/api/admin/schools", validateBody(createSchoolSchema), controller.createSchool);
    app.patch("/api/admin/schools/:id", validateBody(updateSchoolSchema), controller.updateSchool);
    app.patch("/api/admin/schools/:id/deactivate", controller.deactivateSchool);
    app.patch("/api/admin/schools/:id/activate", controller.activateSchool);
    app.post("/api/admin/schools/:id/subscription/pay", validateBody(schoolSubscriptionPaymentSchema), controller.recordSchoolSubscriptionPayment);
    app.delete("/api/admin/schools/:id", controller.deleteSchool);

    app.get("/api/admin/students", controller.listStudents);
    app.post("/api/admin/students", validateBody(createStudentSchema), controller.createStudent);

    app.get("/api/admin/teachers", controller.listTeachers);
    app.post("/api/admin/teachers", validateBody(createTeacherSchema), controller.createTeacher);
}
