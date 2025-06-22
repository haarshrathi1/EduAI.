/**
 * otp-db.js - SQL OTP operations
 */
import { getDb } from './database.js';

/**
 * Set an OTP code for an email
 * @param {string} email - The email to set the OTP for
 * @param {string} code - The OTP code
 * @param {number} expires - The timestamp when the OTP expires
 * @returns {Promise<void>}
 */
export async function setOTP(email, code, expires) {
  const db = await getDb();
  try {
    // Convert the expires timestamp to ISO string
    const expiresDate = new Date(expires).toISOString();
    
    // First delete any existing OTP for this email
    await db.run('DELETE FROM otps WHERE email = ?', [email]);
    
    // Then insert the new OTP
    await db.run(
      'INSERT INTO otps (email, code, expires) VALUES (?, ?, ?)',
      [email, code, expiresDate]
    );
  } finally {
    await db.close();
  }
}

/**
 * Get an OTP record for an email
 * @param {string} email - The email to get the OTP for
 * @returns {Promise<Object|null>} The OTP record or null if not found
 */
export async function getOTP(email) {
  const db = await getDb();
  try {
    const otp = await db.get('SELECT * FROM otps WHERE email = ?', [email]);
    
    if (!otp) {
      return null;
    }
    
    // Parse the expires date to a timestamp
    return {
      code: otp.code,
      expires: new Date(otp.expires).getTime()
    };
  } finally {
    await db.close();
  }
}

/**
 * Remove an OTP record for an email
 * @param {string} email - The email to remove the OTP for
 * @returns {Promise<boolean>} True if removed, false if not found
 */
export async function removeOTP(email) {
  const db = await getDb();
  try {
    const result = await db.run('DELETE FROM otps WHERE email = ?', [email]);
    return result.changes > 0;
  } finally {
    await db.close();
  }
}

/**
 * Clean up expired OTPs
 * @returns {Promise<number>} The number of removed expired OTPs
 */
export async function cleanupExpiredOTPs() {
  const db = await getDb();
  try {
    const now = new Date().toISOString();
    const result = await db.run('DELETE FROM otps WHERE expires < ?', [now]);
    return result.changes;
  } finally {
    await db.close();
  }
}