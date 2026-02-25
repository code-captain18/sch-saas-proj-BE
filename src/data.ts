export type School = {
    id: string;
    name: string;
    district: string;
    totalStudents: number;
    activeTeachers: number;
};

export type DashboardStats = {
    totalSchools: number;
    totalStudents: number;
    attendanceRate: number;
    feeCollectionRate: number;
};

export const schools: School[] = [
    {
        id: "sch_001",
        name: "Riverdale High School",
        district: "North District",
        totalStudents: 1200,
        activeTeachers: 62,
    },
    {
        id: "sch_002",
        name: "Green Valley Public School",
        district: "East District",
        totalStudents: 930,
        activeTeachers: 48,
    },
    {
        id: "sch_003",
        name: "Lakeside Academy",
        district: "Central District",
        totalStudents: 780,
        activeTeachers: 41,
    },
];

export const dashboardStats: DashboardStats = {
    totalSchools: schools.length,
    totalStudents: schools.reduce((sum, school) => sum + school.totalStudents, 0),
    attendanceRate: 94.2,
    feeCollectionRate: 88.7,
};
