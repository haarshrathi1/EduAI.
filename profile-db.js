/**
 * profile-db.js - SQL Profile operations
 */
import { getDb } from './database.js';
import { findUserByEmail } from './user-db.js';

/**
 * Get a user's profile by email
 * @param {string} email - The user's email
 * @returns {Promise<Object|null>} The profile object or null if not found
 */
export async function getProfileByEmail(email) {
  const db = await getDb();
  try {
    // First get the user ID
    const user = await findUserByEmail(email);
    if (!user) {
      return null;
    }

    // Then get the profile
    const profile = await db.get(
      `SELECT p.*, u.email, u.username 
       FROM profiles p
       JOIN users u ON p.user_id = u.id
       WHERE u.email = ?`,
      [email]
    );

    if (!profile) {
      return null;
    }

    // Return a simplified profile object
    return {
      email: profile.email,
      username: profile.username,
      bio: profile.bio,
      location: profile.location,
      website: profile.website
    };
  } finally {
    await db.close();
  }
}

/**
 * Get a user's profile by ID
 * @param {number} userId - The user ID
 * @returns {Promise<Object|null>} The profile object or null if not found
 */
export async function getProfileById(userId) {
  const db = await getDb();
  try {
    const profile = await db.get(
      `SELECT p.*, u.email, u.username 
       FROM profiles p
       JOIN users u ON p.user_id = u.id
       WHERE p.user_id = ?`,
      [userId]
    );

    if (!profile) {
      return null;
    }

    return {
      email: profile.email,
      username: profile.username,
      bio: profile.bio,
      location: profile.location,
      website: profile.website
    };
  } finally {
    await db.close();
  }
}

/**
 * Update a user's profile or password
 * @param {string} email - The user's email
 * @param {Object} updates - The fields to update (bio, location, website, password)
 * @returns {Promise<Object|null>} The updated profile or null if not found
 */
export async function updateProfile(email, updates) {
  const db = await getDb();
  try {
    const user = await findUserByEmail(email);
    if (!user) {
      return null;
    }

    const allowedProfileFields = ['bio', 'location', 'website'];
    const updateProfileEntries = Object.entries(updates).filter(
      ([key]) => allowedProfileFields.includes(key)
    );

    if (updateProfileEntries.length > 0) {
      const setClause = updateProfileEntries.map(([key]) => `${key} = ?`).join(', ');
      const values = updateProfileEntries.map(([, value]) => value);
      values.push(new Date().toISOString());
      values.push(user.id);

      await db.run(
        `UPDATE profiles 
         SET ${setClause}, updated_at = ?
         WHERE user_id = ?`,
        values
      );
    }

    // Handle password update separately in users table
    if (updates.password) {
      await db.run(
        `UPDATE users
         SET password = ?
         WHERE id = ?`,
        [updates.password, user.id]
      );
    }

    return await getProfileByEmail(email);
  } finally {
    await db.close();
  }
}
