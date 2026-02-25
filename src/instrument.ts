// Sentry instrumentation file - must be imported first
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import * as Sentry from "@sentry/node";
import { nodeProfilingIntegration } from "@sentry/profiling-node";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load environment variables
dotenv.config({ path: path.resolve(__dirname, "../.env") });

// Initialize Sentry before any other imports
if (process.env.SENTRY_DSN) {
    Sentry.init({
        dsn: process.env.SENTRY_DSN,
        environment: process.env.NODE_ENV || "development",
        integrations: [
            nodeProfilingIntegration(),
        ],
        // Performance Monitoring
        tracesSampleRate: process.env.NODE_ENV === "production" ? 0.1 : 1.0,
        // Profiling
        profilesSampleRate: process.env.NODE_ENV === "production" ? 0.1 : 1.0,
    });
    console.log(`✓ Sentry initialized in ${process.env.NODE_ENV || "development"} mode`);
} else {
    console.log("! Sentry DSN not configured - error tracking disabled");
}
