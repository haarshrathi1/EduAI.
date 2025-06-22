/**
 * user-db.js - SQL User operations
 */
import { getDb } from './database.js';

/**
 * Find a user by email
 * @param {string} email - The email to search for
 * @returns {Promise<Object|null>} The user object or null if not found
 */
export async function findUserByEmail(email) {
  const db = await getDb();
  try {
    const user = await db.get('SELECT * FROM users WHERE email = ?', [email]);
    return user || null;
  } finally {
    await db.close();
  }
}

/**
 * Find a user by ID
 * @param {number} id - The user ID to search for
 * @returns {Promise<Object|null>} The user object or null if not found
 */
export async function findUserById(id) {
  const db = await getDb();
  try {
    const user = await db.get('SELECT * FROM users WHERE id = ?', [id]);
    return user || null;
  } finally {
    await db.close();
  }
}

/**
 * Create a new user
 * @param {Object} userData - The user data object
 * @param {string} userData.username - The username
 * @param {string} userData.email - The email
 * @param {string} userData.password - The hashed password
 * @returns {Promise<Object>} The created user object
 */
export async function createUser(userData) {
  const db = await getDb();
  try {
    const { username, email, password } = userData;
    
    // Begin a transaction
    await db.run('BEGIN TRANSACTION');
    
    // Insert the user
    const result = await db.run(
      'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
      [username, email, password]
    );
    
    const userId = result.lastID;
    
    // Create an empty profile for the user
    await db.run(
      'INSERT INTO profiles (user_id, bio) VALUES (?, ?)',
      [userId, `Hello, I'm ${username}.`]
    );
    
    // Commit the transaction
    await db.run('COMMIT');
    
    // Return the created user
    return await findUserById(userId);
  } catch (err) {
    // Rollback in case of error
    await db.run('ROLLBACK');
    throw err;
  } finally {
    await db.close();
  }
}

/**
 * Get all users (admin function)
 * @returns {Promise<Array>} Array of user objects
 */
export async function getAllUsers() {
  const db = await getDb();
  try {
    const users = await db.all('SELECT id, username, email, created_at FROM users');
    return users;
  } finally {
    await db.close();
  }
}

/**
 * Update a user
 * @param {number} userId - The user ID to update
 * @param {Object} updates - The fields to update
 * @returns {Promise<Object>} The updated user object
 */
export async function updateUser(userId, updates) {
  const db = await getDb();
  try {
    const allowedUpdates = ['username', 'password'];
    const updateEntries = Object.entries(updates)
      .filter(([key]) => allowedUpdates.includes(key));
    
    if (updateEntries.length === 0) {
      return await findUserById(userId);
    }
    
    const setClause = updateEntries
      .map(([key]) => `${key} = ?`)
      .join(', ');
    
    const values = updateEntries.map(([, value]) => value);
    values.push(userId);
    
    await db.run(`UPDATE users SET ${setClause} WHERE id = ?`, values);
    
    return await findUserById(userId);
  } finally {
    await db.close();
  }
}

/**
 * Delete a user
 * @param {number} userId - The user ID to delete
 * @returns {Promise<boolean>} True if deleted, false if not found
 */
export async function deleteUser(userId) {
  const db = await getDb();
  try {
    const result = await db.run('DELETE FROM users WHERE id = ?', [userId]);
    return result.changes > 0;
  } finally {
    await db.close();
  }
}

/**
 * Add a refresh token for a user
 * @param {number} userId - The user ID
 * @param {string} token - The refresh token
 * @param {Date} expires - The expiration date
 * @returns {Promise<void>}
 */
export async function addRefreshToken(userId, token, expires) {
  const db = await getDb();
  try {
    await db.run(
      'INSERT INTO refresh_tokens (user_id, token, expires) VALUES (?, ?, ?)',
      [userId, token, expires.toISOString()]
    );
  } finally {
    await db.close();
  }
}

/**
 * Verify a refresh token
 * @param {string} token - The refresh token to verify
 * @returns {Promise<Object|null>} The token record if valid, null otherwise
 */
export async function verifyRefreshToken(token) {
  const db = await getDb();
  try {
    const now = new Date().toISOString();
    
    // Get the token record and associated user
    const tokenRecord = await db.get(
      `SELECT rt.*, u.email, u.username 
       FROM refresh_tokens rt
       JOIN users u ON rt.user_id = u.id
       WHERE rt.token = ? AND rt.expires > ?`,
      [token, now]
    );
    
    return tokenRecord || null;
  } finally {
    await db.close();
  }
}

/**
 * Remove a refresh token
 * @param {string} token - The refresh token to remove
 * @returns {Promise<boolean>} True if removed, false if not found
 */
export async function removeRefreshToken(token) {
  const db = await getDb();
  try {
    const result = await db.run('DELETE FROM refresh_tokens WHERE token = ?', [token]);
    return result.changes > 0;
  } finally {
    await db.close();
  }
}