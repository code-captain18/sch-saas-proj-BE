import { Request, Response, NextFunction } from "express";
import { z, ZodError, ZodIssue } from "zod";

type RequestWithValidatedQuery = Request & {
    validatedQuery?: Record<string, unknown>;
};

export function validateBody<T extends z.ZodTypeAny>(schema: T) {
    return async (req: Request, res: Response, next: NextFunction) => {
        try {
            req.body = await schema.parseAsync(req.body);
            next();
        } catch (error) {
            if (error instanceof ZodError) {
                const errors = error.issues.map((err: ZodIssue) => ({
                    field: err.path.join("."),
                    message: err.message,
                }));
                return res.status(400).json({
                    error: "Validation failed",
                    details: errors,
                });
            }
            next(error);
        }
    };
}

export function validateQuery<T extends z.ZodTypeAny>(schema: T) {
    return async (req: Request, res: Response, next: NextFunction) => {
        try {
            // Convert query string values to appropriate types
            const query: Record<string, unknown> = { ...req.query };

            // Convert numeric strings to numbers for fields that should be numbers
            if (query.limit && typeof query.limit === "string") {
                query.limit = Number(query.limit);
            }

            const validated = await schema.parseAsync(query);
            (req as RequestWithValidatedQuery).validatedQuery = validated as Record<string, unknown>;
            next();
        } catch (error) {
            if (error instanceof ZodError) {
                const errors = error.issues.map((err: ZodIssue) => ({
                    field: err.path.join("."),
                    message: err.message,
                }));
                return res.status(400).json({
                    error: "Invalid query parameters",
                    details: errors,
                });
            }
            next(error);
        }
    };
}
