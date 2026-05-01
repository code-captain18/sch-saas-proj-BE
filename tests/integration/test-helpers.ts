import jwt from "jsonwebtoken";

export function createAccessToken(payload: { sub: string; role: string; schoolId?: string | null; userType?: string }) {
    const secret = process.env.JWT_SECRET ?? process.env.AUTH_JWT_SECRET ?? "dev-only-change-me";
    return jwt.sign(payload, secret, { expiresIn: "15m" });
}

export function stubPrismaMethod<TObj extends object, TKey extends keyof TObj>(
    obj: TObj,
    key: TKey,
    impl: TObj[TKey],
): () => void {
    const original = obj[key];
    (obj as Record<string, unknown>)[String(key)] = impl as unknown;
    return () => {
        (obj as Record<string, unknown>)[String(key)] = original as unknown;
    };
}