import assert from "node:assert/strict";
import test from "node:test";

import { generateOtp, getGuardianPhones, otpExpiresAt } from "../src/lib/sms.js";

test("generateOtp returns a 6-digit numeric string", () => {
    const otp = generateOtp();
    assert.match(otp, /^\d{6}$/);
});

test("generateOtp has high variability across multiple calls", () => {
    const values = new Set(Array.from({ length: 100 }, () => generateOtp()));
    // Non-flaky uniqueness check; collisions are possible but very unlikely at this threshold.
    assert.ok(values.size > 90, `Expected >90 unique OTPs, got ${values.size}`);
});

test("otpExpiresAt defaults to around 10 minutes", () => {
    const now = Date.now();
    const expires = otpExpiresAt();
    const diff = expires.getTime() - now;

    // Allow small scheduling/runtime drift.
    assert.ok(diff >= 9.5 * 60 * 1000, `Expected >= 9.5 minutes, got ${diff}ms`);
    assert.ok(diff <= 10.5 * 60 * 1000, `Expected <= 10.5 minutes, got ${diff}ms`);
});

test("otpExpiresAt accepts custom minutes", () => {
    const now = Date.now();
    const expires = otpExpiresAt(15);
    const diff = expires.getTime() - now;

    assert.ok(diff >= 14.5 * 60 * 1000, `Expected >= 14.5 minutes, got ${diff}ms`);
    assert.ok(diff <= 15.5 * 60 * 1000, `Expected <= 15.5 minutes, got ${diff}ms`);
});

test("getGuardianPhones extracts and trims guardian phone numbers", () => {
    const guardianInfo = {
        father: { phone: " 0244000001 " },
        mother: { phone: "0244000002" },
        emergency: { phone: "" },
    };

    const phones = getGuardianPhones(guardianInfo);

    assert.deepEqual(phones, ["0244000001", "0244000002"]);
});

test("getGuardianPhones returns empty array for null/non-object", () => {
    assert.deepEqual(getGuardianPhones(null), []);
    assert.deepEqual(getGuardianPhones(undefined), []);
    assert.deepEqual(getGuardianPhones("not-an-object"), []);
});
