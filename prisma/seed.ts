/// <reference types="node" />

import bcrypt from "bcryptjs";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

type SchoolFixture = {
    name: string;
    district: string;
    address: string;
    phone: string;
    email: string;
    domain: string;
    principalName: string;
    schoolAdminName: string;
    accountantName: string;
    staffName: string;
    viewerName: string;
};

const schoolFixtures: SchoolFixture[] = [
    {
        name: "Riverdale High School",
        district: "North District",
        address: "123 Main St, Riverdale",
        phone: "+1-555-0100",
        email: "contact@riverdalehigh.edu",
        domain: "riverdalehigh.edu",
        principalName: "Ama Agyemang",
        schoolAdminName: "Kofi Mensah",
        accountantName: "Yaw Addo",
        staffName: "Akosua Asante",
        viewerName: "Esi Owusu",
    },
    {
        name: "Green Valley Public School",
        district: "East District",
        address: "456 Oak Ave, Green Valley",
        phone: "+1-555-0200",
        email: "info@greenvalley.edu",
        domain: "greenvalley.edu",
        principalName: "Nana Boateng",
        schoolAdminName: "Linda Kwarteng",
        accountantName: "Prince Ofori",
        staffName: "Mabel Antwi",
        viewerName: "Kojo Badu",
    },
    {
        name: "Lakeside Academy",
        district: "Central District",
        address: "789 Lake Road, Lakeside",
        phone: "+1-555-0300",
        email: "admin@lakesideacademy.edu",
        domain: "lakesideacademy.edu",
        principalName: "Adwoa Nyarko",
        schoolAdminName: "Richard Frimpong",
        accountantName: "Belinda Ntim",
        staffName: "Samuel Arthur",
        viewerName: "Abena Serwaa",
    },
    {
        name: "Sunrise International School",
        district: "West District",
        address: "18 Sunrise Boulevard, Asokwa",
        phone: "+1-555-0400",
        email: "office@sunriseinternational.edu",
        domain: "sunriseinternational.edu",
        principalName: "Michael Danquah",
        schoolAdminName: "Patricia Lawson",
        accountantName: "Irene Appiah",
        staffName: "Stephen Tetteh",
        viewerName: "Gladys Annan",
    },
];

const classTemplates = [
    { name: "JHS 1A", grade: "JHS 1", section: "A", feeAmount: 1200 },
    { name: "JHS 2A", grade: "JHS 2", section: "A", feeAmount: 1350 },
];

const subjectTemplates = [
    { name: "Mathematics", code: "MATH" },
    { name: "English Language", code: "ENG" },
    { name: "Integrated Science", code: "SCI" },
    { name: "Social Studies", code: "SOC" },
];

const studentNames = [
    ["Kwame", "Asare"],
    ["Abena", "Bonsu"],
    ["Kojo", "Amoah"],
    ["Akua", "Boateng"],
    ["Yaw", "Kusi"],
    ["Efua", "Sarpong"],
    ["Nii", "Laryea"],
    ["Adjoa", "Darko"],
];

const teacherProfiles = [
    { firstName: "John", lastName: "Smith", subject: "Mathematics" },
    { firstName: "Sarah", lastName: "Johnson", subject: "English Language" },
    { firstName: "Daniel", lastName: "Cole", subject: "Integrated Science" },
    { firstName: "Martha", lastName: "Adams", subject: "Social Studies" },
];

const otpPhones = ["233205032649", "233249433172"] as const;

function pickOtpPhone(index: number) {
    return otpPhones[index % otpPhones.length];
}

function addDays(baseDate: Date, days: number) {
    const next = new Date(baseDate);
    next.setDate(next.getDate() + days);
    return next;
}

function termFromIndex(index: number): "TERM_1" | "TERM_2" | "TERM_3" {
    if (index % 3 === 0) return "TERM_1";
    if (index % 3 === 1) return "TERM_2";
    return "TERM_3";
}

async function main() {
    console.log("Seeding database...");

    await prisma.feePayment.deleteMany();
    await prisma.feeInvoice.deleteMany();
    await prisma.feeStructure.deleteMany();
    await prisma.assignmentSubmission.deleteMany();
    await prisma.assignment.deleteMany();
    await prisma.score.deleteMany();
    await prisma.teachingAssignment.deleteMany();
    await prisma.classSubject.deleteMany();
    await prisma.attendance.deleteMany();
    await prisma.timetable.deleteMany();
    await prisma.otpToken.deleteMany();
    await prisma.authSession.deleteMany();
    await prisma.auditLog.deleteMany();
    await prisma.schoolSettings.deleteMany();
    await prisma.student.deleteMany();
    await prisma.subject.deleteMany();
    await prisma.class.deleteMany();
    await prisma.teacher.deleteMany();
    await prisma.adminUser.deleteMany();
    await prisma.school.deleteMany();

    const superAdminPasswordHash = await bcrypt.hash("SuperAdmin@123", 10);
    const principalPasswordHash = await bcrypt.hash("Principal@123", 10);
    const schoolAdminPasswordHash = await bcrypt.hash("SchoolAdmin@123", 10);
    const accountantPasswordHash = await bcrypt.hash("Accountant@123", 10);
    const staffPasswordHash = await bcrypt.hash("Staff@123", 10);
    const viewerPasswordHash = await bcrypt.hash("Viewer@123", 10);
    const teacherPasswordHash = await bcrypt.hash("Teacher@123", 10);

    await prisma.adminUser.create({
        data: {
            name: "Platform Super Admin",
            email: "superadmin@schoolflow.com",
            passwordHash: superAdminPasswordHash,
            phone: pickOtpPhone(0),
            role: "SUPER_ADMIN",
        },
    });

    for (let schoolIndex = 0; schoolIndex < schoolFixtures.length; schoolIndex += 1) {
        const fixture = schoolFixtures[schoolIndex]!;
        const school = await prisma.school.create({
            data: {
                name: fixture.name,
                district: fixture.district,
                address: fixture.address,
                phone: fixture.phone,
                email: fixture.email,
                totalStudents: 0,
                activeTeachers: 0,
            },
        });

        await prisma.adminUser.createMany({
            data: [
                {
                    name: fixture.principalName,
                    email: `principal@${fixture.domain}`,
                    passwordHash: principalPasswordHash,
                    phone: pickOtpPhone(schoolIndex),
                    role: "PRINCIPAL",
                    schoolId: school.id,
                },
                {
                    name: fixture.schoolAdminName,
                    email: `schooladmin@${fixture.domain}`,
                    passwordHash: schoolAdminPasswordHash,
                    phone: pickOtpPhone(schoolIndex + 1),
                    role: "SCHOOL_ADMIN",
                    schoolId: school.id,
                },
                {
                    name: fixture.accountantName,
                    email: `accounts@${fixture.domain}`,
                    passwordHash: accountantPasswordHash,
                    phone: pickOtpPhone(schoolIndex + 2),
                    role: "ACCOUNTANT",
                    schoolId: school.id,
                },
                {
                    name: fixture.staffName,
                    email: `staff@${fixture.domain}`,
                    passwordHash: staffPasswordHash,
                    phone: pickOtpPhone(schoolIndex + 3),
                    role: "STAFF",
                    schoolId: school.id,
                },
                {
                    name: fixture.viewerName,
                    email: `viewer@${fixture.domain}`,
                    passwordHash: viewerPasswordHash,
                    phone: pickOtpPhone(schoolIndex + 4),
                    role: "VIEWER",
                    schoolId: school.id,
                },
            ],
        });

        const teachers = await Promise.all(
            teacherProfiles.map((profile, profileIndex) =>
                prisma.teacher.create({
                    data: {
                        firstName: profile.firstName,
                        lastName: `${profile.lastName}-${schoolIndex + 1}`,
                        email: `${profile.firstName.toLowerCase()}.${profile.lastName.toLowerCase()}.${schoolIndex + 1}@${fixture.domain}`,
                        passwordHash: teacherPasswordHash,
                        phone: pickOtpPhone(schoolIndex + profileIndex),
                        subject: profile.subject,
                        schoolId: school.id,
                    },
                }),
            ),
        );

        const classes = await Promise.all(
            classTemplates.map((classTemplate, classIndex) =>
                prisma.class.create({
                    data: {
                        name: classTemplate.name,
                        grade: classTemplate.grade,
                        section: classTemplate.section,
                        academicYear: "2025-2026",
                        feeAmount: classTemplate.feeAmount,
                        schoolId: school.id,
                        teacherId: teachers[classIndex]?.id ?? null,
                        assistantTeacherId: teachers[classIndex + 2]?.id ?? null,
                    },
                }),
            ),
        );

        const subjects = await Promise.all(
            subjectTemplates.map((subjectTemplate) =>
                prisma.subject.create({
                    data: {
                        name: subjectTemplate.name,
                        code: `${subjectTemplate.code}-${schoolIndex + 1}`,
                        description: `${subjectTemplate.name} curriculum for ${fixture.name}`,
                        schoolId: school.id,
                    },
                }),
            ),
        );

        await prisma.classSubject.createMany({
            data: classes.flatMap((schoolClass) =>
                subjects.map((subject) => ({
                    classId: schoolClass.id,
                    subjectId: subject.id,
                })),
            ),
        });

        await prisma.teachingAssignment.createMany({
            data: classes.flatMap((schoolClass, classIndex) => {
                const classTeacher = teachers[classIndex];
                if (!classTeacher) return [];
                return subjects.slice(0, 2).map((subject) => ({
                    schoolId: school.id,
                    teacherId: classTeacher.id,
                    classId: schoolClass.id,
                    subjectId: subject.id,
                }));
            }),
        });

        const students = await Promise.all(
            studentNames.map(([firstName, lastName], studentIndex) => {
                const assignedClass = classes[studentIndex % classes.length]!;
                return prisma.student.create({
                    data: {
                        firstName,
                        lastName,
                        email: `${firstName.toLowerCase()}.${lastName.toLowerCase()}.${schoolIndex + 1}@students.${fixture.domain}`,
                        dateOfBirth: new Date(2011, studentIndex % 12, (studentIndex % 27) + 1),
                        guardianInfo: {
                            father: {
                                firstName: `Guardian${studentIndex + 1}`,
                                lastName,
                                phone: pickOtpPhone(schoolIndex + studentIndex),
                            },
                        },
                        schoolId: school.id,
                        classId: assignedClass.id,
                    },
                });
            }),
        );

        const today = new Date();
        today.setHours(0, 0, 0, 0);

        await prisma.attendance.createMany({
            data: students.flatMap((student, studentIndex) => {
                const studentClassId = student.classId ?? classes[0]!.id;
                return [0, 1, 2].map((offset) => ({
                    date: addDays(today, -offset),
                    status: (studentIndex + offset) % 6 === 0 ? "LATE" : (studentIndex + offset) % 7 === 0 ? "ABSENT" : "PRESENT",
                    remarks: (studentIndex + offset) % 6 === 0 ? "Arrived after morning assembly" : null,
                    schoolId: school.id,
                    studentId: student.id,
                    classId: studentClassId,
                }));
            }),
        });

        const feeStructures = await Promise.all(
            classes.map((schoolClass, classIndex) =>
                prisma.feeStructure.create({
                    data: {
                        schoolId: school.id,
                        title: `${schoolClass.name} Tuition Package`,
                        academicYear: "2025-2026",
                        term: termFromIndex(classIndex),
                        scopeType: "CLASS",
                        classId: schoolClass.id,
                        items: [
                            { label: "Tuition", amount: 900 + classIndex * 100 },
                            { label: "ICT", amount: 120 },
                            { label: "Exam", amount: 80 },
                        ],
                        totalAmount: 1100 + classIndex * 100,
                    },
                }),
            ),
        );

        for (let studentIndex = 0; studentIndex < students.length; studentIndex += 1) {
            const student = students[studentIndex]!;
            const matchingClassIndex = classes.findIndex((schoolClass) => schoolClass.id === student.classId);
            const feeStructure = feeStructures[Math.max(0, matchingClassIndex)]!;
            const invoiceAmount = Number(feeStructure.totalAmount);

            const invoice = await prisma.feeInvoice.create({
                data: {
                    schoolId: school.id,
                    studentId: student.id,
                    amount: invoiceAmount,
                    status: studentIndex % 3 === 0 ? "PARTIALLY_PAID" : studentIndex % 3 === 1 ? "PAID" : "PENDING",
                    term: feeStructure.term,
                    academicYear: feeStructure.academicYear,
                    dueDate: new Date("2026-09-10T00:00:00.000Z"),
                    description: `${feeStructure.title} invoice`,
                    lineItems: feeStructure.items,
                    feeStructureId: feeStructure.id,
                },
            });

            if (studentIndex % 3 !== 2) {
                await prisma.feePayment.create({
                    data: {
                        invoiceId: invoice.id,
                        amount: studentIndex % 3 === 1 ? invoiceAmount : Math.floor(invoiceAmount * 0.5),
                        method: studentIndex % 2 === 0 ? "ONLINE" : "BANK_TRANSFER",
                        reference: `TXN-${schoolIndex + 1}-${studentIndex + 1000}`,
                    },
                });
            }
        }

        await prisma.school.update({
            where: { id: school.id },
            data: {
                totalStudents: students.length,
                activeTeachers: teachers.length,
            },
        });
    }

    console.log("Database seeded successfully!");
    console.log(`Created ${await prisma.school.count()} schools`);
    console.log(`Created ${await prisma.adminUser.count()} admin users`);
    console.log(`Created ${await prisma.teacher.count()} teachers`);
    console.log(`Created ${await prisma.class.count()} classes`);
    console.log(`Created ${await prisma.subject.count()} subjects`);
    console.log(`Created ${await prisma.student.count()} students`);
    console.log(`Created ${await prisma.attendance.count()} attendance records`);
    console.log(`Created ${await prisma.feeStructure.count()} fee structures`);
    console.log(`Created ${await prisma.feeInvoice.count()} fee invoices`);
    console.log(`Created ${await prisma.feePayment.count()} fee payments`);

    console.log("\n=== Login Credentials (Seeded) ===");
    console.log("SUPER_ADMIN  -> superadmin@schoolflow.com / SuperAdmin@123");
    console.log("PRINCIPAL    -> principal@<school-domain> / Principal@123");
    console.log("SCHOOL_ADMIN -> schooladmin@<school-domain> / SchoolAdmin@123");
    console.log("ACCOUNTANT   -> accounts@<school-domain> / Accountant@123");
    console.log("STAFF        -> staff@<school-domain> / Staff@123");
    console.log("VIEWER       -> viewer@<school-domain> / Viewer@123");
    console.log("TEACHER      -> <firstname>.<lastname>.<schoolIndex>@<school-domain> / Teacher@123");

    console.log("\nSchool Domains:");
    for (const fixture of schoolFixtures) {
        console.log(`- ${fixture.name}: ${fixture.domain}`);
    }
}

main()
    .catch((e) => {
        console.error("Error seeding database:", e);
        process.exit(1);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });
