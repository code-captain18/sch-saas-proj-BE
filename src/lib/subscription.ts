export type SchoolSubscriptionSnapshot = {
    isActive: boolean;
    createdAt: Date;
    subscriptionStartedAt: Date;
    subscriptionTrialEndsAt: Date | null;
    subscriptionPaidUntil: Date | null;
};

export type SubscriptionStatus = "TRIAL" | "ACTIVE" | "PAST_DUE";

const isTestRunnerProcess = process.argv.some(
    (arg) => arg === "--test" || arg.endsWith(".test.ts") || arg.endsWith(".test.js"),
);

export function isSubscriptionEnforcementEnabled() {
    if (process.env.SUBSCRIPTION_ENFORCEMENT === "true") return true;
    if (process.env.SUBSCRIPTION_ENFORCEMENT === "false") return false;
    return process.env.NODE_ENV !== "test" && !isTestRunnerProcess;
}

export function addMonths(date: Date, months: number) {
    const next = new Date(date);
    next.setMonth(next.getMonth() + months);
    return next;
}

export function resolveTrialEndsAt(school: Pick<SchoolSubscriptionSnapshot, "subscriptionStartedAt" | "subscriptionTrialEndsAt">) {
    return school.subscriptionTrialEndsAt ?? addMonths(school.subscriptionStartedAt, 4);
}

export function getSchoolSubscriptionStatus(school: SchoolSubscriptionSnapshot, now = new Date()): SubscriptionStatus {
    const trialEndsAt = resolveTrialEndsAt(school);

    if (now <= trialEndsAt) {
        return "TRIAL";
    }

    if (school.subscriptionPaidUntil && school.subscriptionPaidUntil >= now) {
        return "ACTIVE";
    }

    return "PAST_DUE";
}

export function canSchoolAccess(school: SchoolSubscriptionSnapshot, now = new Date()) {
    if (!school.isActive) {
        return {
            allowed: false,
            reason: "School is inactive. Contact support.",
        };
    }

    const status = getSchoolSubscriptionStatus(school, now);
    if (status === "PAST_DUE") {
        return {
            allowed: false,
            reason: "Subscription expired. Please renew your monthly plan.",
        };
    }

    return {
        allowed: true,
        reason: null,
    };
}