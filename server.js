/*************************************************
 * server.js - Updated to use GPT-4.1 for all AI responses,
 * including text, file, and image analysis.
 *************************************************/

import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import path from 'path';
import { fileURLToPath } from 'url';
import OpenAI from 'openai';
import nodemailer from 'nodemailer';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import multer from 'multer';
// Use promises-based file I/O to avoid blocking the event loop
import fs from 'fs/promises';
import Tesseract from 'tesseract.js'; // For OCR on images

/*************************************************
 * Local Database Modules
 *************************************************/
import { initializeDb } from './database.js';
import {
  findUserByEmail,
  createUser,
  addRefreshToken,
  verifyRefreshToken,
  removeRefreshToken
} from './user-db.js';
import { setOTP, getOTP, removeOTP, cleanupExpiredOTPs } from './otp-db.js';
import { storeQuery, getUserQueries } from './queries-db.js';
import { getProfileByEmail, updateProfile } from './profile-db.js';
// (Removed generateMedicalResponse, isMedicalQuestion as they’re no longer used)

/*************************************************
 * Hardcoded Secrets (not recommended for production)
 *************************************************/
const SECRET_KEY = 'YOUR_SUPER_SECRET_KEY_HERE';
const REFRESH_SECRET_KEY = 'YOUR_SUPER_REFRESH_SECRET_KEY_HERE';
const OPENAI_API_KEY = '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';
const EMAIL_USER = 'popoipika@gmail.com';
const EMAIL_PASS = 'wmvo ochw emsk fkiq';
const EMAIL_SERVICE = 'gmail';

/*************************************************
 * OTP & Token Expiry
 *************************************************/
const OTP_EXPIRATION_MINUTES = 10; // OTP expires in 10 minutes
const ACCESS_TOKEN_EXPIRY = '15m'; // Access token valid for 15 minutes
const REFRESH_TOKEN_EXPIRY = '7d';  // Refresh token valid for 7 days

/*************************************************
 * ESM __dirname Workaround
 *************************************************/
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/*************************************************
 * Express App Setup
 *************************************************/
const app = express();

// Enable 'trust proxy' to allow express-rate-limit to properly detect client IPs
app.set('trust proxy', 1);

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));

/*************************************************
 * Serve Static Files
 *************************************************/
app.use(express.static(path.join(__dirname, 'public')));

/*************************************************
 * Initialize Database
 *************************************************/
async function setupDatabase() {
  try {
    await initializeDb();
    console.log('Database initialized successfully');

    // Setup scheduled cleanup for expired OTPs every 15 minutes
    setInterval(async () => {
      try {
        const removed = await cleanupExpiredOTPs();
        if (removed > 0) {
          console.log(`Cleaned up ${removed} expired OTPs`);
        }
      } catch (err) {
        console.error('Error cleaning up OTPs:', err);
      }
    }, 15 * 60 * 1000);
  } catch (err) {
    console.error('Database initialization failed:', err);
    process.exit(1);
  }
}
setupDatabase();

/*************************************************
 * Nodemailer Setup
 *************************************************/
const transporter = nodemailer.createTransport({
  service: EMAIL_SERVICE,
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS,
  }
});

/*************************************************
 * Helper: Send OTP
 *************************************************/
async function sendOTP(email, code) {
  const mailOptions = {
    from: EMAIL_USER,
    to: email,
    subject: 'Your OTP Code',
    text: `Your OTP code is: ${code}`,
  };
  return transporter.sendMail(mailOptions);
}

/*************************************************
 * JWT Middleware
 *************************************************/
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'No token provided' });
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token missing' });
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = decoded;
    next();
  });
}

/*************************************************
 * Password Strength Check
 *************************************************/
function isStrongPassword(password) {
  if (password.length < 8) return false;
  if (!/[A-Z]/.test(password)) return false;
  if (!/[a-z]/.test(password)) return false;
  if (!/\d/.test(password)) return false;
  return true;
}

/*************************************************
 * Rate Limiters
 *************************************************/
const signupLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many signup attempts, please try again later.' }
});
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: 'Too many login attempts, please try again later.' }
});
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: 'Too many OTP verification attempts, please try again later.' }
});
// Note: The ask and analyze endpoints have no rate limits so that anyone can ask any question

/*************************************************
 * Initialize OpenAI - now using GPT-4.1 for all calls
 *************************************************/
const openai = new OpenAI({ apiKey: OPENAI_API_KEY });
// NOTE: Ensure that 'gpt-4.1' is the correct model name for your API access

/*************************************************
 * Simple AI Response Cache (in-memory)
 *************************************************/
const aiCache = new Map();
function getCachedAnswer(question, tag) {
  const key = `${question.toLowerCase()}_${tag}`;
  const entry = aiCache.get(key);
  return entry ? entry.answer : null;
}
function setCachedAnswer(question, tag, answer) {
  const key = `${question.toLowerCase()}_${tag}`;
  aiCache.set(key, { answer, timestamp: Date.now() });
}

/*************************************************
 * Health Check
 *************************************************/
app.get('/health', (req, res) => {
  res.json({ status: 'ok', message: 'PocketDocAI server is running smoothly.' });
});

/*************************************************
 * Front-End Routes
 *************************************************/
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});
app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});
app.get('/otp', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'otp.html'));
});
app.get('/ai', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'ai-interface.html'));
});
app.get('/faq', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'faq.html'));
});

/*************************************************
 * Signup - with OTP
 *************************************************/
app.post('/signup', signupLimiter, async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password)
      return res.status(400).json({ error: 'Missing required fields' });
    if (!isStrongPassword(password))
      return res.status(400).json({ error: 'Password too weak. Must be at least 8 characters with uppercase, lowercase, and a digit.' });

    const existingUser = await findUserByEmail(email);
    if (existingUser)
      return res.status(409).json({ error: 'User already exists with this email' });

    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = Date.now() + OTP_EXPIRATION_MINUTES * 60 * 1000;
    await setOTP(email, otpCode, expires);
    await sendOTP(email, otpCode);

    return res.status(200).json({ message: 'OTP sent to email. Please verify to complete signup.', tempData: { username, email } });
  } catch (err) {
    console.error('Signup Error:', err);
    return res.status(500).json({ error: 'Server error during signup' });
  }
});

/*************************************************
 * Verify OTP => Create User
 *************************************************/
app.post('/verify-otp', otpLimiter, async (req, res) => {
  try {
    const { username, email, password, otp } = req.body;
    if (!username || !email || !password || !otp)
      return res.status(400).json({ error: 'Missing required fields' });

    const stored = await getOTP(email);
    if (!stored)
      return res.status(400).json({ error: 'No OTP request found for this email' });
    if (stored.expires < Date.now()) {
      await removeOTP(email);
      return res.status(400).json({ error: 'OTP expired. Please request a new one.' });
    }
    if (stored.code !== otp)
      return res.status(400).json({ error: 'Invalid OTP code' });

    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = await createUser({ username, email, password: hashedPassword });
    await removeOTP(email);

    const token = jwt.sign({ email: newUser.email, username: newUser.username }, SECRET_KEY, { expiresIn: ACCESS_TOKEN_EXPIRY });
    const refreshToken = jwt.sign({ email: newUser.email, username: newUser.username }, REFRESH_SECRET_KEY, { expiresIn: REFRESH_TOKEN_EXPIRY });
    const expiresDate = new Date();
    expiresDate.setDate(expiresDate.getDate() + 7);
    await addRefreshToken(newUser.id, refreshToken, expiresDate);

    return res.status(201).json({ message: 'User signed up successfully', token, refreshToken });
  } catch (err) {
    console.error('OTP Verification Error:', err);
    return res.status(500).json({ error: 'Server error during OTP verification' });
  }
});

/*************************************************
 * Login Endpoint
 *************************************************/
app.post('/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Missing email or password' });

    const user = await findUserByEmail(email);
    if (!user)
      return res.status(404).json({ error: 'No user found with this email' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(401).json({ error: 'Invalid credentials' });

    const accessToken = jwt.sign({ email: user.email, username: user.username, id: user.id }, SECRET_KEY, { expiresIn: ACCESS_TOKEN_EXPIRY });
    const refreshToken = jwt.sign({ email: user.email, username: user.username, id: user.id }, REFRESH_SECRET_KEY, { expiresIn: REFRESH_TOKEN_EXPIRY });
    const expiresDate = new Date();
    expiresDate.setDate(expiresDate.getDate() + 7);
    await addRefreshToken(user.id, refreshToken, expiresDate);

    return res.status(200).json({ message: 'Login successful', token: accessToken, refreshToken });
  } catch (err) {
    console.error('Login Error:', err);
    return res.status(500).json({ error: 'Server error during login' });
  }
});

/*************************************************
 * Refresh Token Endpoint
 *************************************************/
app.post('/token/refresh', async (req, res) => {
  try {
    const { token } = req.body;
    if (!token)
      return res.status(400).json({ error: 'No refresh token provided' });

    const tokenRecord = await verifyRefreshToken(token);
    if (!tokenRecord)
      return res.status(403).json({ error: 'Invalid or expired refresh token' });

    const newAccessToken = jwt.sign({ email: tokenRecord.email, username: tokenRecord.username, id: tokenRecord.user_id }, SECRET_KEY, { expiresIn: ACCESS_TOKEN_EXPIRY });
    return res.json({ token: newAccessToken });
  } catch (err) {
    console.error('Token Refresh Error:', err);
    return res.status(500).json({ error: 'Server error during token refresh' });
  }
});

/*************************************************
 * Logout Endpoint (Invalidate Refresh Token)
 *************************************************/
app.post('/logout', async (req, res) => {
  try {
    const { token } = req.body;
    if (!token)
      return res.status(400).json({ error: 'No refresh token provided' });
    await removeRefreshToken(token);
    return res.json({ message: 'Logged out successfully' });
  } catch (err) {
    console.error('Logout Error:', err);
    return res.status(500).json({ error: 'Server error during logout' });
  }
});
/*************************************************
 * Reset Password After OTP Verification
 *************************************************/
app.post('/reset-password', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword)
      return res.status(400).json({ error: 'Missing email, OTP, or new password' });

    const stored = await getOTP(email);
    if (!stored)
      return res.status(400).json({ error: 'No OTP request found for this email' });

    if (stored.expires < Date.now()) {
      await removeOTP(email);
      return res.status(400).json({ error: 'OTP expired. Please request again.' });
    }

    if (stored.code !== otp)
      return res.status(400).json({ error: 'Invalid OTP code' });

    if (!isStrongPassword(newPassword))
      return res.status(400).json({
        error: 'Password too weak. Must be at least 8 characters with uppercase, lowercase, and a digit.'
      });

    const hashedPassword = await bcrypt.hash(newPassword, 12);

    // Update user password
    const user = await findUserByEmail(email);
    if (!user) return res.status(404).json({ error: 'User not found' });

    await updateProfile(email, { password: hashedPassword });
    await removeOTP(email);

    return res.status(200).json({ message: 'Password reset successful' });
  } catch (err) {
    console.error('Reset Password Error:', err);
    return res.status(500).json({ error: 'Server error during password reset' });
  }
});

/*************************************************
 * Multer Setup for File Upload
 *************************************************/
const upload = multer({ dest: 'uploads/' });

/*************************************************
 * File Upload Endpoint (simple)
 *************************************************/
app.post('/api/upload', authenticateToken, upload.single('file'), (req, res) => {
  if (!req.file)
    return res.status(400).json({ error: 'No file provided' });
  console.log(`File uploaded: ${req.file.originalname}`);
  return res.json({ message: 'File uploaded successfully' });
});

/*************************************************
 * File/Image Analysis with GPT-4.1 (unified for all types)
 *************************************************/
app.post('/api/analyze', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    if (!req.file)
      return res.status(400).json({ error: 'No file provided for analysis' });

    const isImage = req.file.mimetype.startsWith('image/');
    const fileBuffer = await fs.readFile(req.file.path);
    await fs.unlink(req.file.path); // delete after reading

    const messages = [
      {
        role: 'system',
        content: 'You are a professional doctor providing clear, accurate, and evidence-based medical interpretation in Markdown format. If the input is an image, analyze it like a radiologist or clinical expert. If it is text, give detailed advice.'
      }
    ];

    if (isImage) {
      // image input for GPT-4.1 vision model
      messages.push({
        role: 'user',
        content: [
          {
            type: 'image_url',
            image_url: {
              url: `data:${req.file.mimetype};base64,${fileBuffer.toString('base64')}`
            }
          }
        ]
      });
    } else {
      // text input
      const textContent = fileBuffer.toString('utf-8');
      messages.push({
        role: 'user',
        content: `Please analyze the following content:\n\n${textContent}`
      });
    }

    const response = await openai.chat.completions.create({
      model: 'gpt-4.1',
      messages: messages
    });

    if (!response.choices || !response.choices.length)
      throw new Error('No response from GPT-4.1');

    const analysis = response.choices[0].message.content.trim();

    if (req.user?.email)
      await storeQuery(req.user.email, '(file/image analysis)', analysis);

    return res.status(200).json({ analysis });
  } catch (error) {
    console.error('File/Image Analysis Error:', error.response || error.message);
    return res.status(500).json({ error: 'Error analyzing file or image' });
  }
});

/*************************************************
 * Chat Endpoint (Ask AI) - Fine-tuned for specific medical questions
 *************************************************/
app.post('/api/ask', authenticateToken, async (req, res) => {
  const { question } = req.body;
  if (!question)
    return res.status(400).json({ error: 'No question provided' });

  // Check cache first
  const cached = getCachedAnswer(question, 'gpt-4.1');
  if (cached)
    return res.status(200).json({ answer: cached, cached: true });

  try {
    const systemPrompt = `You are a professional doctor providing detailed, evidence-based medical advice in Markdown format.

- Respond specifically and precisely to the medical question asked.
- Use clear, simple language and medical terminology where appropriate.
- Include common symptoms, potential causes, preventive measures, and targeted guidance.
- Explicitly recommend immediate medical consultation if symptoms indicate serious or life-threatening conditions.
- Advise consulting a healthcare provider for unclear, uncertain, or complex conditions.`;

    const response = await openai.chat.completions.create({
      model: 'gpt-4.1',
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: question }
      ],
      max_completion_tokens: 700,
      temperature: 0.5,
    });

    if (!response.choices || !response.choices.length) {
      throw new Error('No response choices received from OpenAI');
    }

    const aiAnswer = response.choices[0].message.content.trim();
    setCachedAnswer(question, 'gpt-4.1', aiAnswer);

    if (req.user?.email)
      await storeQuery(req.user.email, question, aiAnswer);

    return res.status(200).json({ answer: aiAnswer, cached: false });
  } catch (error) {
    console.error('Ask AI Error:', error.response || error.message);
    return res.status(500).json({ error: 'Error processing question' });
  }
});

/*************************************************
 * AI-Powered FAQ Endpoint - Now using GPT-4.1
 *************************************************/
app.get('/api/faq', async (req, res) => {
  const key = 'faq-page';
  const cached = getCachedAnswer(key, 'gpt-4.1');
  if (cached)
    return res.json({ faq: cached });
  
  const prompt = `
You are a professional doctor acting as an AI assistant. Provide a user-friendly FAQ for a medical AI assistant website addressing:
• The reliability of answers.
• Whether doctors review the content.
• How to trust the AI.
• Account requirements.
• The different user categories.
Answer in Markdown using bullet points.
  `;
  try {
    const response = await openai.chat.completions.create({
      model: 'gpt-4.1',
      messages: [{ role: 'user', content: prompt }],
      max_completion_tokens: 400,
      temperature: 0.7,
    });
    if (!response.choices || !response.choices.length) {
      throw new Error('No response choices received from OpenAI');
    }
    const faqContent = response.choices[0].message.content.trim();
    setCachedAnswer(key, 'gpt-4.1', faqContent);
    return res.json({ faq: faqContent });
  } catch (error) {
    console.error('FAQ Error:', error.response || error.message);
    return res.status(500).json({ error: 'Error fetching FAQ' });
  }
});

/*************************************************
 * Basic User Profile Endpoints
 *************************************************/
// GET profile
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const userEmail = req.user.email;
    const userProfile = await getProfileByEmail(userEmail);
    if (!userProfile)
      return res.status(404).json({ error: 'Profile not found' });
    return res.json({ profile: userProfile });
  } catch (err) {
    console.error('Get Profile Error:', err);
    return res.status(500).json({ error: 'Server error getting profile' });
  }
});

// UPDATE profile
app.put('/api/profile', authenticateToken, async (req, res) => {
  try {
    const userEmail = req.user.email;
    const { bio, location, website } = req.body;
    const updatedProfile = await updateProfile(userEmail, {
      bio: bio !== undefined ? bio : undefined,
      location: location !== undefined ? location : undefined,
      website: website !== undefined ? website : undefined
    });
    if (!updatedProfile)
      return res.status(404).json({ error: 'Profile not found' });
    return res.json({ message: 'Profile updated', profile: updatedProfile });
  } catch (err) {
    console.error('Update Profile Error:', err);
    return res.status(500).json({ error: 'Server error updating profile' });
  }
});

// GET query history
app.get('/api/queries', authenticateToken, async (req, res) => {
  try {
    const userEmail = req.user.email;
    const limit = parseInt(req.query.limit) || 20;
    const offset = parseInt(req.query.offset) || 0;
    const queries = await getUserQueries(userEmail, limit, offset);
    return res.json({ queries });
  } catch (err) {
    console.error('Get Queries Error:', err);
    return res.status(500).json({ error: 'Server error getting query history' });
  }
});

/*************************************************
 * Image/Document Analysis Endpoint - Smart model switching
 * OCR text from any file (Tesseract + GPT-4.1-mini) or, if recognized as an X-ray/CT/MRI, use GPT-4.1 vision analysis.
 *************************************************/
app.post('/api/analyze-file', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    // Ensure a file was provided
    if (!req.file)
      return res.status(400).json({ error: 'No file provided for analysis' });

    // Basic X-ray/scan detection based on filename patterns
    const isXrayOrScan = /xray|ct|scan|mri/i.test(req.file.originalname);

    // If recognized as an X-ray, scan, or MRI image, use GPT-4.1 for medical interpretation
    if (isXrayOrScan) {
      const fileBuffer = await fs.readFile(req.file.path);
      await fs.unlink(req.file.path);

      // GPT-4.1 radiology-like analysis
      const response = await openai.chat.completions.create({
        model: 'gpt-4.1',
        messages: [
          {
            role: 'system',
            content: 'You are a professional radiologist. Analyze the provided medical image (e.g., X-ray, CT scan) and give a clear, evidence-based medical interpretation in Markdown.'
          },
          {
            role: 'user',
            content: [
              {
                type: 'image_url',
                image_url: { url: `data:${req.file.mimetype};base64,${fileBuffer.toString('base64')}` }
              }
            ]
          }
        ]
      });

      if (!response.choices || !response.choices.length)
        throw new Error('No response from GPT-4.1 vision analysis');

      const analysis = response.choices[0].message.content.trim();
      if (req.user?.email)
        await storeQuery(req.user.email, '(image interpretation)', analysis);

      return res.status(200).json({ analysis });
    } else {
      let extractedText = '';

      // OCR extraction for all file types
      const { data: { text } } = await Tesseract.recognize(req.file.path, 'eng');
      extractedText = text;
      await fs.unlink(req.file.path);

      // Pass extracted text to language model (using GPT-4.1-mini) for analysis.
      const systemPrompt = 'You are a professional doctor. Based on the extracted text, provide expert, evidence-based medical advice in Markdown.';
      const userPrompt = `Analyze the following extracted medical information and provide your expert advice:\n\n${extractedText}`;

      const response = await openai.chat.completions.create({
        model: 'gpt-4.1-mini',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt }
        ]
      });

      if (!response.choices || !response.choices.length)
        throw new Error('No response from GPT-4.1-mini OCR analysis');

      const analysis = response.choices[0].message.content.trim();
      if (req.user?.email)
        await storeQuery(req.user.email, '(file OCR)', analysis);

      return res.status(200).json({ analysis });
    }

  } catch (error) {
    console.error('File Analysis Error:', error.response || error.message);
    return res.status(500).json({ error: 'Error analyzing file' });
  }
});

/*************************************************
 * Start Server
 *************************************************/
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
