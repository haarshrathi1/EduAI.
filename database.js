/**
 * database.js - SQL Database Connection and Setup
 */
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

// Get the directory name
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Database file path
const dbPath = path.join(__dirname, 'pocketdoc.db');

// SQL file path for schema
const schemaPath = path.join(__dirname, 'schema.sql');

/**
 * Initialize the database connection
 * @returns {Promise<sqlite.Database>} The database connection
 */
async function getDb() {
  // Open the database
  const db = await open({
    filename: dbPath,
    driver: sqlite3.Database
  });
  
  // Enable foreign keys
  await db.exec('PRAGMA foreign_keys = ON');
  
  return db;
}

/**
 * Initialize the database schema if it doesn't exist
 */
async function initializeDb() {
  const db = await getDb();
  
  try {
    // Check if the users table exists (as a proxy for checking if DB is initialized)
    const userTable = await db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='users'");
    
    if (!userTable) {
      console.log('Initializing database schema...');
      
      // If schema.sql file exists, use it to initialize the database
      if (fs.existsSync(schemaPath)) {
        const schema = fs.readFileSync(schemaPath, 'utf8');
        await db.exec(schema);
        console.log('Database schema initialized from file');
      } else {
        // Otherwise, create the schema directly here
        await db.exec(`
          -- Users table
          CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          );
          
          -- User profiles table
          CREATE TABLE profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            bio TEXT DEFAULT '',
            location TEXT DEFAULT '',
            website TEXT DEFAULT '',
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
          );
          
          -- OTP storage table
          CREATE TABLE otps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            code TEXT NOT NULL,
            expires TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          );
          
          -- Query history table
          CREATE TABLE queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            question TEXT NOT NULL,
            answer TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
          );
          
          -- Refresh tokens table
          CREATE TABLE refresh_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
          );
          
          -- Create indexes for performance
          CREATE INDEX idx_users_email ON users(email);
          CREATE INDEX idx_otps_email ON otps(email);
          CREATE INDEX idx_queries_user_id ON queries(user_id);
          CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(token);
        `);
        console.log('Database schema initialized in code');
      }
    }
  } catch (err) {
    console.error('Database initialization error:', err);
    throw err;
  } finally {
    await db.close();
  }
}

// Export the functions
export { getDb, initializeDb };