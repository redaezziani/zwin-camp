import { PrismaClient, Role } from '@prisma/client';
import * as bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
  console.log('Start seeding...');
  
  // Hash passwords for security
  const saltRounds = 10;
  const defaultPassword = await bcrypt.hash('password123', saltRounds);
  const adminPassword = await bcrypt.hash('admin123', saltRounds);
  
  // Create regular users
  const users = [
    {
      email: 'user1@example.com',
      name: 'John Doe',
      password: defaultPassword,
      role: Role.USER,
      isEmailVerified: true,
    },
    {
      email: 'user2@example.com',
      name: 'Jane Smith',
      password: defaultPassword,
      role: Role.USER,
      isEmailVerified: true,
    },
    {
      email: 'user3@example.com',
      name: 'Bob Johnson',
      password: defaultPassword,
      role: Role.USER,
      isEmailVerified: false,
    },
  ];

  // Create an admin user
  const admin = {
    email: 'admin@example.com',
    name: 'Admin User',
    password: adminPassword,
    role: Role.ADMIN,
    isEmailVerified: true,
  };

  // Insert users
  for (const user of users) {
    const existingUser = await prisma.user.findUnique({
      where: { email: user.email },
    });

    if (!existingUser) {
      const createdUser = await prisma.user.create({
        data: user,
      });
      console.log(`Created user with id: ${createdUser.id}`);
    } else {
      console.log(`User with email ${user.email} already exists`);
    }
  }

  // Insert admin
  const existingAdmin = await prisma.user.findUnique({
    where: { email: admin.email },
  });

  if (!existingAdmin) {
    const createdAdmin = await prisma.user.create({
      data: admin,
    });
    console.log(`Created admin with id: ${createdAdmin.id}`);
  } else {
    console.log(`Admin with email ${admin.email} already exists`);
  }

  console.log('Seeding finished');
}

main()
  .then(async () => {
    await prisma.$disconnect();
  })
  .catch(async (e) => {
    console.error(e);
    await prisma.$disconnect();
    process.exit(1);
  });