/**
 * setup.js - Installation and Setup Script for PocketDocAI
 * 
 * This script:
 * 1. Creates the schema.sql file if it doesn't exist
 * 2. Initializes the SQLite database
 * 3. Checks for required dependencies
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';
import { initializeDb } from './database.js';

// Get the directory name
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// SQL Schema file path
const schemaPath = path.join(__dirname, 'schema.sql');

// Dependencies required for the application
const requiredDependencies = [
  'sqlite3',
  'sqlite',
  'express',
  'cors',
  'bcryptjs',
  'jsonwebtoken',
  'openai',
  'nodemailer',
  'morgan',
  'express-rate-limit',
  'multer'
];

/**
 * Create SQL schema file
 */
function createSchemaFile() {
  if (fs.existsSync(schemaPath)) {
    console.log('Schema file already exists, skipping creation');
    return;
  }

  console.log('Creating SQL schema file...');
  const schemaContent = `-- Database schema for PocketDocAI application

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
`;

  fs.writeFileSync(schemaPath, schemaContent, 'utf8');
  console.log('Schema file created successfully');
}

/**
 * Check if required dependencies are installed
 */
async function checkDependencies() {
  console.log('Checking dependencies...');
  
  try {
    const packageJsonPath = path.join(__dirname, 'package.json');
    if (!fs.existsSync(packageJsonPath)) {
      console.log('package.json not found, creating a basic one...');
      
      const packageJson = {
        "name": "pocketdoc-ai",
        "version": "1.0.0",
        "description": "PocketDocAI - Medical AI Assistant",
        "main": "server.js",
        "type": "module",
        "scripts": {
          "start": "node server.js",
          "setup": "node setup.js"
        },
        "dependencies": {}
      };
      
      fs.writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2), 'utf8');
      console.log('Basic package.json created');
    }
    
    console.log('Installing required dependencies...');
    execSync(`npm install ${requiredDependencies.join(' ')}`, { stdio: 'inherit' });
    console.log('Dependencies installed successfully');
  } catch (err) {
    console.error('Error checking or installing dependencies:', err);
    process.exit(1);
  }
}

/**
 * Main setup function
 */
async function setup() {
  console.log('Starting PocketDocAI setup...');
  
  try {
    // Create the schema file
    createSchemaFile();
    
    // Check and install dependencies
    await checkDependencies();
    
    // Initialize the database
    console.log('Initializing database...');
    await initializeDb();
    console.log('Database initialized successfully');
    
    console.log('\nSetup completed successfully!');
    console.log('\nTo start the server, run:');
    console.log('npm start');
  } catch (err) {
    console.error('Setup failed:', err);
    process.exit(1);
  }
}

// Run the setup
setup();
