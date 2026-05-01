ALTER TABLE "schools"
    ADD COLUMN "subscription_started_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ADD COLUMN "subscription_trial_ends_at" TIMESTAMP(3),
    ADD COLUMN "subscription_paid_until" TIMESTAMP(3),
    ADD COLUMN "subscription_monthly_fee" DECIMAL(10,2) NOT NULL DEFAULT 0;

UPDATE "schools"
SET "subscription_trial_ends_at" = "subscription_started_at" + INTERVAL '4 months'
WHERE "subscription_trial_ends_at" IS NULL;
