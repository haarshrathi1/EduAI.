/**
 * queries-db.js - SQL Query history operations
 */
import { getDb } from './database.js';
import { findUserByEmail } from './user-db.js';

/**
 * Store a user's query
 * @param {string} email - The user's email
 * @param {string} question - The question asked
 * @param {string} answer - The answer provided
 * @returns {Promise<void>}
 */
export async function storeQuery(email, question, answer) {
  const db = await getDb();
  try {
    // First get the user ID
    const user = await findUserByEmail(email);
    
    if (!user) {
      // Store as anonymous query
      await db.run(
        'INSERT INTO queries (question, answer) VALUES (?, ?)',
        [question, answer]
      );
    } else {
      // Store with user ID
      await db.run(
        'INSERT INTO queries (user_id, question, answer) VALUES (?, ?, ?)',
        [user.id, question, answer]
      );
    }
  } finally {
    await db.close();
  }
}

/**
 * Get a user's query history
 * @param {string} email - The user's email
 * @param {number} limit - The maximum number of queries to return
 * @param {number} offset - The offset for pagination
 * @returns {Promise<Array>} Array of query objects
 */
export async function getUserQueries(email, limit = 100, offset = 0) {
  const db = await getDb();
  try {
    // First get the user ID
    const user = await findUserByEmail(email);
    
    if (!user) {
      return [];
    }
    
    const queries = await db.all(
      `SELECT * FROM queries 
       WHERE user_id = ? 
       ORDER BY timestamp DESC 
       LIMIT ? OFFSET ?`,
      [user.id, limit, offset]
    );
    
    return queries;
  } finally {
    await db.close();
  }
}

/**
 * Get total count of a user's queries
 * @param {string} email - The user's email
 * @returns {Promise<number>} The total count
 */
export async function getUserQueryCount(email) {
  const db = await getDb();
  try {
    // First get the user ID
    const user = await findUserByEmail(email);
    
    if (!user) {
      return 0;
    }
    
    const result = await db.get(
      'SELECT COUNT(*) as count FROM queries WHERE user_id = ?',
      [user.id]
    );
    
    return result.count;
  } finally {
    await db.close();
  }
}

/**
 * Delete a query by ID
 * @param {number} queryId - The query ID
 * @param {string} userEmail - The user's email (for authorization)
 * @returns {Promise<boolean>} True if deleted, false if not found or not authorized
 */
export async function deleteQuery(queryId, userEmail) {
  const db = await getDb();
  try {
    // First get the user ID
    const user = await findUserByEmail(userEmail);
    
    if (!user) {
      return false;
    }
    
    // Delete the query if it belongs to the user
    const result = await db.run(
      'DELETE FROM queries WHERE id = ? AND user_id = ?',
      [queryId, user.id]
    );
    
    return result.changes > 0;
  } finally {
    await db.close();
  }
}