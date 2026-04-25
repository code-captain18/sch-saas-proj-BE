# SchoolFlow Backend

Express + TypeScript API with PostgreSQL + Prisma for the SchoolFlow SaaS starter.

## Setup

```bash
npm install
cp .env.example .env
```

Edit `.env` and set your environment variables:

```env
# Server Configuration
PORT=4000
NODE_ENV=development

# Database (PostgreSQL - Neon or local)
DATABASE_URL=postgresql://user:password@localhost:5432/schoolflow

# Redis (recommended for distributed OTP throttling)
REDIS_URL=redis://localhost:6379

# JWT Secret (use a strong random string)
JWT_SECRET=your-secret-key-here

# Sentry (Error tracking and performance monitoring)
SENTRY_DSN="your-sentry-dsn-here"

# SMS provider credentials
SMS_USERNAME=your-sms-username
SMS_PASSWORD=your-sms-password
SMS_SENDER_ID=KGM

# OTP security throttling (milliseconds for *_MS)
OTP_SEND_WINDOW_MS=600000
OTP_SEND_COOLDOWN_MS=60000
OTP_VERIFY_WINDOW_MS=600000
OTP_SEND_IP_LIMIT=20
OTP_SEND_USER_LIMIT=5
OTP_VERIFY_IP_LIMIT=30
OTP_VERIFY_CHALLENGE_LIMIT=5
OTP_SEND_IP_BLOCK_MS=900000
OTP_SEND_USER_BLOCK_MS=600000
OTP_VERIFY_BLOCK_MS=900000
```

### Sentry Setup

1. Create a free account at [sentry.io](https://sentry.io/)
2. Create a new project (choose Node.js/Express)
3. Copy your DSN and add it to `.env`

The backend includes:
- Request tracing and performance monitoring
- Profiling integration for performance insights
- Error tracking with stack traces
- Automatic environment detection
- Sampling rates optimized for development and production

### Validation

All API endpoints use Zod for input validation:
- Request body validation
- Query parameter validation
- Type-safe error responses


## Database Setup

```bash
# Generate Prisma Client
npm run db:generate

# Run migrations to create tables
npm run db:migrate

# Seed the database with sample data
npm run db:seed

# Open Prisma Studio to view/edit data
npm run db:studio
```

## Development

```bash
npm run dev
```

Server runs on `http://localhost:4000`.

## Endpoints

- `GET /api/health` - Health check with database status
- `GET /api/dashboard/stats` - Dashboard metrics (schools, students, attendance, etc.)
- `GET /api/schools` - List all schools
- `GET /api/schools/:id` - Get school details with students, teachers, and classes

## Database Schema

- **School** - School information
- **Student** - Student records with enrollment status
- **Teacher** - Teacher profiles
- **Class** - Classes/sections per school
- **Attendance** - Daily attendance tracking per student/class
