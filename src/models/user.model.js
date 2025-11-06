import { pgTable, serial, varchar, timestamp} from "drizzle-orm/pg-core";

// Define the schema for the users table
export const users = pgTable('users', {
    id: serial('id').primaryKey(),
    name: varchar('name', {length: 255}).notNull(),
    email: varchar('email', {length: 255}).notNull().unique(),
    password: varchar('password', {length: 255}).notNull(),
    role: varchar('role', {length: 50}).notNull(),
    created_at: timestamp().defaultNow().notNull(),
    updated_at: timestamp().defaultNow().notNull(),
})