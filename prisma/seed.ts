/// <reference types="node" />

import bcrypt from "bcryptjs";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function main() {
    console.log("Seeding database...");

    await prisma.feePayment.deleteMany();
    await prisma.feeInvoice.deleteMany();
    await prisma.classSubject.deleteMany();
    await prisma.attendance.deleteMany();
    await prisma.student.deleteMany();
    await prisma.subject.deleteMany();
    await prisma.class.deleteMany();
    await prisma.teacher.deleteMany();
    await prisma.adminUser.deleteMany();
    await prisma.school.deleteMany();

    // Create schools
    const school1 = await prisma.school.create({
        data: {
            name: "Riverdale High School",
            district: "North District",
            address: "123 Main St, Riverdale",
            phone: "+1-555-0100",
            email: "contact@riverdalehigh.edu",
            totalStudents: 1200,
            activeTeachers: 62,
        },
    });

    const school2 = await prisma.school.create({
        data: {
            name: "Green Valley Public School",
            district: "East District",
            address: "456 Oak Ave, Green Valley",
            phone: "+1-555-0200",
            email: "info@greenvalley.edu",
            totalStudents: 930,
            activeTeachers: 48,
        },
    });

    const school3 = await prisma.school.create({
        data: {
            name: "Lakeside Academy",
            district: "Central District",
            address: "789 Lake Road, Lakeside",
            phone: "+1-555-0300",
            email: "admin@lakesideacademy.edu",
            totalStudents: 780,
            activeTeachers: 41,
        },
    });

    const superAdminPasswordHash = await bcrypt.hash("SuperAdmin@123", 10);
    const schoolAdminPasswordHash = await bcrypt.hash("SchoolAdmin@123", 10);
    const accountantPasswordHash = await bcrypt.hash("Accountant@123", 10);
    const staffPasswordHash = await bcrypt.hash("Staff@123", 10);
    const viewerPasswordHash = await bcrypt.hash("Viewer@123", 10);
    const teacherPasswordHash = await bcrypt.hash("Teacher@123", 10);

    await prisma.adminUser.createMany({
        data: [
            {
                name: "Platform Super Admin",
                email: "superadmin@schoolflow.com",
                passwordHash: superAdminPasswordHash,
                role: "SUPER_ADMIN",
            },
            {
                name: "Riverdale Admin",
                email: "admin@riverdalehigh.edu",
                passwordHash: schoolAdminPasswordHash,
                role: "SCHOOL_ADMIN",
                schoolId: school1.id,
            },
            {
                name: "Riverdale Accountant",
                email: "accounts@riverdalehigh.edu",
                passwordHash: accountantPasswordHash,
                role: "ACCOUNTANT",
                schoolId: school1.id,
            },
            {
                name: "Riverdale Staff",
                email: "staff@riverdalehigh.edu",
                passwordHash: staffPasswordHash,
                role: "STAFF",
                schoolId: school1.id,
            },
            {
                name: "Riverdale Viewer",
                email: "viewer@riverdalehigh.edu",
                passwordHash: viewerPasswordHash,
                role: "VIEWER",
                schoolId: school1.id,
            },
        ],
    });

    // Create teachers
    const teacher1 = await prisma.teacher.create({
        data: {
            firstName: "John",
            lastName: "Smith",
            email: "john.smith@riverdalehigh.edu",
            passwordHash: teacherPasswordHash,
            phone: "+1-555-1001",
            subject: "Mathematics",
            schoolId: school1.id,
        },
    });

    const teacher2 = await prisma.teacher.create({
        data: {
            firstName: "Sarah",
            lastName: "Johnson",
            email: "sarah.johnson@greenvalley.edu",
            passwordHash: teacherPasswordHash,
            phone: "+1-555-1002",
            subject: "English",
            schoolId: school2.id,
        },
    });

    // Create classes
    const class1 = await prisma.class.create({
        data: {
            name: "Mathematics 10A",
            grade: "10",
            section: "A",
            academicYear: "2025-2026",
            feeAmount: 4500,
            schoolId: school1.id,
            teacherId: teacher1.id,
        },
    });

    const class2 = await prisma.class.create({
        data: {
            name: "English 9B",
            grade: "9",
            section: "B",
            academicYear: "2025-2026",
            feeAmount: 3200,
            schoolId: school2.id,
            teacherId: teacher2.id,
        },
    });

    const mathSubject = await prisma.subject.create({
        data: {
            name: "Mathematics",
            code: "MATH-10",
            description: "Core high school mathematics",
            schoolId: school1.id,
        },
    });

    const englishSubject = await prisma.subject.create({
        data: {
            name: "English Language",
            code: "ENG-09",
            description: "Language and composition",
            schoolId: school2.id,
        },
    });

    await prisma.classSubject.createMany({
        data: [
            { classId: class1.id, subjectId: mathSubject.id },
            { classId: class2.id, subjectId: englishSubject.id },
        ],
    });

    // Create students
    const student1 = await prisma.student.create({
        data: {
            firstName: "Alice",
            lastName: "Williams",
            email: "alice.williams@student.riverdalehigh.edu",
            dateOfBirth: new Date("2009-05-15"),
            schoolId: school1.id,
            classId: class1.id,
        },
    });

    const student2 = await prisma.student.create({
        data: {
            firstName: "Bob",
            lastName: "Davis",
            email: "bob.davis@student.riverdalehigh.edu",
            dateOfBirth: new Date("2009-08-22"),
            schoolId: school1.id,
            classId: class1.id,
        },
    });

    const student3 = await prisma.student.create({
        data: {
            firstName: "Carol",
            lastName: "Martinez",
            email: "carol.martinez@student.greenvalley.edu",
            dateOfBirth: new Date("2010-02-10"),
            schoolId: school2.id,
            classId: class2.id,
        },
    });

    // Create attendance records
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    await prisma.attendance.createMany({
        data: [
            {
                date: today,
                status: "PRESENT",
                schoolId: school1.id,
                studentId: student1.id,
                classId: class1.id,
            },
            {
                date: today,
                status: "PRESENT",
                schoolId: school1.id,
                studentId: student2.id,
                classId: class1.id,
            },
            {
                date: today,
                status: "LATE",
                schoolId: school2.id,
                studentId: student3.id,
                classId: class2.id,
                remarks: "Arrived 15 minutes late",
            },
        ],
    });

    const invoice1 = await prisma.feeInvoice.create({
        data: {
            schoolId: school1.id,
            studentId: student1.id,
            amount: 1200,
            dueDate: new Date("2026-03-10"),
            status: "PARTIALLY_PAID",
            description: "Term 2 tuition fee",
        },
    });

    const invoice2 = await prisma.feeInvoice.create({
        data: {
            schoolId: school1.id,
            studentId: student2.id,
            amount: 1000,
            dueDate: new Date("2026-03-10"),
            status: "PENDING",
            description: "Term 2 tuition fee",
        },
    });

    await prisma.feePayment.create({
        data: {
            invoiceId: invoice1.id,
            amount: 600,
            method: "ONLINE",
            reference: "TXN-RHS-1001",
        },
    });

    console.log("Database seeded successfully!");
    console.log(`Created ${await prisma.school.count()} schools`);
    console.log(`Created ${await prisma.adminUser.count()} admin users`);
    console.log(`Created ${await prisma.teacher.count()} teachers`);
    console.log(`Created ${await prisma.class.count()} classes`);
    console.log(`Created ${await prisma.subject.count()} subjects`);
    console.log(`Created ${await prisma.student.count()} students`);
    console.log(`Created ${await prisma.attendance.count()} attendance records`);
    console.log(`Created ${await prisma.feeInvoice.count()} fee invoices`);
    console.log(`Created ${await prisma.feePayment.count()} fee payments`);
}

main()
    .catch((e) => {
        console.error("Error seeding database:", e);
        process.exit(1);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });
