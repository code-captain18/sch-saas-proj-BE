# Setup Local PostgreSQL for Development

## Option 1: Docker (Easiest)
```bash
# Run PostgreSQL in Docker
docker run -d \
  --name school-db \
  -e POSTGRES_PASSWORD=dev123 \
  -e POSTGRES_DB=schooldb \
  -p 5432:5432 \
  postgres:16

# Update .env
DATABASE_URL="postgresql://postgres:dev123@localhost:5432/schooldb?sslmode=disable"
```

## Option 2: Install PostgreSQL Locally
1. Download from: https://www.postgresql.org/download/windows/
2. Install with password: `dev123`
3. Create database: `schooldb`
4. Update .env:
```
DATABASE_URL="postgresql://postgres:dev123@localhost:5432/schooldb"
```

## After Switching
```bash
# Run migrations to create tables
npx prisma migrate deploy

# Seed the database
npx prisma db seed
```

## Benefits
- ✅ Never expires
- ✅ Works offline
- ✅ Faster queries (no network latency)
- ✅ No connection limits
- ✅ Free forever
