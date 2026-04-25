import crypto from "node:crypto";

const smsApiUrl =
    process.env.SMS_API_URL ?? "https://sms.nalosolutions.com/smsbackend/Resl_Nalo/send-message/";
const smsUsername = process.env.SMS_USERNAME ?? "";
const smsPassword = process.env.SMS_PASSWORD ?? "";
const smsSenderId = process.env.SMS_SENDER_ID ?? "KGM";

/**
 * Send an SMS message via the Nalo Solutions API.
 * Never throws — SMS failures are logged but do not block the primary request.
 */
export async function sendSms(msisdn: string, message: string): Promise<void> {
    const phone = msisdn?.trim();
    if (!phone) return;

    if (!smsUsername || !smsPassword) {
        console.warn("[SMS] Credentials not configured. Skipping SMS to", phone);
        return;
    }

    try {
        const response = await fetch(smsApiUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                username: smsUsername,
                password: smsPassword,
                msisdn: phone,
                message,
                sender_id: smsSenderId,
            }),
        });

        if (!response.ok) {
            const text = await response.text().catch(() => "");
            console.error(`[SMS] Send failed (${response.status}):`, text);
        }
    } catch (err) {
        console.error("[SMS] Network error:", err);
    }
}

/** Generate a cryptographically secure 6-digit OTP code. */
export function generateOtp(): string {
    return String(crypto.randomInt(100000, 1000000));
}

/** Return a Date that is `minutes` from now (default 10). */
export function otpExpiresAt(minutes = 10): Date {
    return new Date(Date.now() + minutes * 60 * 1000);
}

/**
 * Extract all non-empty phone numbers from a student's guardianInfo JSON.
 * GuardianInfo shape: { father?: { phone?: string }, mother?: { phone?: string }, ... }
 */
export function getGuardianPhones(guardianInfo: unknown): string[] {
    if (!guardianInfo || typeof guardianInfo !== "object") return [];
    const phones: string[] = [];
    for (const guardian of Object.values(guardianInfo as Record<string, { phone?: string }>)) {
        if (guardian?.phone?.trim()) {
            phones.push(guardian.phone.trim());
        }
    }
    return phones;
}
