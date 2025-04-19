const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const passport = require('passport');
const GitHubStrategy = require('passport-github2').Strategy;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const https = require('https');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
  origin: 'http://localhost:4200',
  credentials: true
}));
app.use(express.json());
app.use(passport.initialize());

// MongoDB Connection
const connectDB = async () => {
  try {
    if (!process.env.MONGODB_URI) {
      throw new Error('MONGODB_URI is not defined in .env file');
    }
    const conn = await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log(`MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error(`Database connection error: ${error.message}`);
    process.exit(1);
  }
};
connectDB();

// User Schema
const UserSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, 'Please add an email'],
    unique: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please add a valid email']
  },
  password: {
    type: String,
    select: false,
    minlength: 6
  },
  secretQuestion: {
    type: String,
    required: [true, 'Please provide a secret question'],
    trim: true
  },
  secretAnswer: {
    type: String,
    required: [true, 'Please provide a secret answer'],
    select: false,
    trim: true
  },
  provider: {
    type: String,
    enum: ['local', 'github'],
    default: 'local'
  },
  providerId: {
    type: String,
    default: null
  },
  username: {
    type: String,
    default: null
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

UserSchema.pre('save', async function(next) {
  if (this.isModified('password') && this.password) {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
  }
  if (this.isModified('secretAnswer') && this.secretAnswer) {
    const salt = await bcrypt.genSalt(10);
    this.secretAnswer = await bcrypt.hash(this.secretAnswer, salt);
  }
  next();
});

const User = mongoose.model('User', UserSchema);

// File Schema
const FileSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  filename: {
    type: String,
    required: [true, 'Please provide a filename'],
    trim: true
  },
  language: {
    type: String,
    required: [true, 'Please specify a language'],
    enum: ['cpp', 'javascript', 'python', 'java']
  },
  code: {
    type: String,
    required: [true, 'Code content is required']
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

FileSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

const File = mongoose.model('File', FileSchema);

// Passport Configuration
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: `${process.env.BASE_URL || 'http://localhost:5000'}/api/auth/github/callback`
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ providerId: profile.id, provider: 'github' });
    
    if (!user) {
      user = await User.findOne({ email: profile.emails && profile.emails[0]?.value });
      
      if (!user) {
        user = new User({
          providerId: profile.id,
          provider: 'github',
          email: profile.emails && profile.emails[0]?.value ? profile.emails[0].value : `${profile.id}@githubuser.com`,
          username: profile.username,
          password: Math.random().toString(36).slice(-8),
          secretQuestion: 'Default question for GitHub users',
          secretAnswer: Math.random().toString(36).slice(-8)
        });
      } else {
        user.providerId = profile.id;
        user.provider = 'github';
        user.username = profile.username;
      }
      await user.save();
    }
    
    return done(null, user);
  } catch (err) {
    console.error('Error in GitHub Strategy:', err);
    return done(err, null);
  }
}));

// Authentication Middleware
const auth = (req, res, next) => {
  const token = req.header('x-auth-token');
  if (!token) {
    return res.status(401).json({ message: 'No token, authorization denied' });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Token is not valid' });
  }
};

// Authentication Routes
const authRoutes = express.Router();

authRoutes.post('/signup', async (req, res) => {
  try {
    const { email, password, secretQuestion, secretAnswer } = req.body;
    if (!email || !password || !secretQuestion || !secretAnswer) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ message: 'User already exists' });
    }
    user = new User({
      email,
      password,
      secretQuestion,
      secretAnswer,
      provider: 'local',
      username: email.split('@')[0]
    });
    await user.save();
    const token = jwt.sign(
      { _id: user._id, email: user.email, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.json({ token });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ message: 'Signup failed: ' + error.message });
  }
});

authRoutes.post('/login', async (req, res) => {
  try {
    const { email, password, secretAnswer } = req.body;
    if (!email || !password || !secretAnswer) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    const user = await User.findOne({ email }).select('+password +secretAnswer');
    if (!user || !user.password) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    const isPasswordMatch = await bcrypt.compare(password, user.password);
    const isAnswerMatch = await bcrypt.compare(secretAnswer, user.secretAnswer);
    if (!isPasswordMatch || !isAnswerMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign(
      { _id: user._id, email: user.email, username: user.username || email.split('@')[0] },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.json({ token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Login failed: ' + error.message });
  }
});

authRoutes.post('/reset-password', async (req, res) => {
  try {
    const { email, secretAnswer, newPassword } = req.body;
    if (!email || !secretAnswer || !newPassword) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    const user = await User.findOne({ email }).select('+secretAnswer +password');
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }
    const isAnswerMatch = await bcrypt.compare(secretAnswer, user.secretAnswer);
    if (!isAnswerMatch) {
      return res.status(400).json({ message: 'Invalid secret answer' });
    }
    user.password = newPassword;
    await user.save();
    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ message: 'Password reset failed: ' + error.message });
  }
});

authRoutes.post('/forgot-password', async (req, res) => {
  try {
    const { email, secretAnswer } = req.body;
    if (!email || !secretAnswer) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    const user = await User.findOne({ email }).select('+secretAnswer');
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }
    const isAnswerMatch = await bcrypt.compare(secretAnswer, user.secretAnswer);
    if (!isAnswerMatch) {
      return res.status(400).json({ message: 'Invalid secret answer' });
    }
    // Note: In a production environment, you would send a reset link or temporary password via email
    // For this example, we'll indicate that the user can proceed to reset
    res.json({ message: 'Secret answer verified. Please proceed to reset your password.' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ message: 'Password retrieval failed: ' + error.message });
  }
});

authRoutes.get('/github', passport.authenticate('github', { scope: ['user', 'user:email'] }));

authRoutes.get('/github/callback',
  passport.authenticate('github', { session: false }),
  (req, res) => {
    try {
      if (!req.user) {
        console.error('GitHub authentication failed: No user found');
        return res.redirect('http://localhost:4200/auth/callback?error=GitHub authentication failed: No user found');
      }
      const token = jwt.sign(
        { _id: req.user._id, email: req.user.email, username: req.user.username },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
      res.redirect(`http://localhost:4200/auth/callback?token=${token}`);
    } catch (error) {
      console.error('GitHub callback error:', error);
      res.redirect(`http://localhost:4200/auth/callback?error=${encodeURIComponent(error.message || 'GitHub callback error')}`);
    }
  }
);

// File Routes
const fileRoutes = express.Router();

fileRoutes.post('/save', auth, async (req, res) => {
  try {
    const { filename, language, code, fileId } = req.body;
    const userId = req.user._id;

    if (!filename || !language || !code) {
      return res.status(400).json({ message: 'Filename, language, and code are required' });
    }

    if (fileId) {
      const file = await File.findOneAndUpdate(
        { _id: fileId, userId },
        { filename, language, code },
        { new: true }
      );
      if (!file) return res.status(404).json({ message: 'File not found or not authorized' });
      res.json({ fileId: file._id, message: 'File updated successfully' });
    } else {
      const file = new File({ userId, filename, language, code });
      await file.save();
      res.json({ fileId: file._id, message: 'File saved successfully' });
    }
  } catch (error) {
    console.error('Error saving file:', error);
    res.status(500).json({ message: 'Failed to save file: ' + error.message });
  }
});

fileRoutes.get('/list', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const files = await File.find({ userId }).sort({ updatedAt: -1 });
    res.json(files);
  } catch (error) {
    console.error('Error fetching files:', error);
    res.status(500).json({ message: 'Failed to fetch files: ' + error.message });
  }
});

fileRoutes.get('/:fileId', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const file = await File.findOne({ _id: req.params.fileId, userId });
    if (!file) return res.status(404).json({ message: 'File not found or not authorized' });
    res.json(file);
  } catch (error) {
    console.error('Error fetching file:', error);
    res.status(500).json({ message: 'Failed to fetch file: ' + error.message });
  }
});

// Piston API Configuration
const PISTON_API_URL = 'https://emkc.org/api/v2/piston/execute';

let languageVersions = {
  'cpp': '10.2.0',
  'javascript': '18.15.0',
  'python': '3.10.0',
  'java': '15.0.2'
};

async function fetchLanguageVersions() {
  try {
    const response = await axios.get('https://emkc.org/api/v2/piston/runtimes');
    const runtimes = response.data;
    
    const supportedLanguages = ['cpp', 'javascript', 'python', 'java'];
    supportedLanguages.forEach(lang => {
      const runtime = runtimes.find(r => r.language === lang);
      if (runtime) {
        languageVersions[lang] = runtime.version;
        console.log(`Fetched ${lang} version: ${languageVersions[lang]}`);
      }
    });
  } catch (error) {
    console.error('Failed to fetch Piston runtimes, using fallbacks:', error.message);
    console.log('Fallback versions:', languageVersions);
  }
}
fetchLanguageVersions();

// Code Execution Endpoint
app.post('/api/run', auth, async (req, res) => {
  const { code, language, input } = req.body;

  if (!code || !language) {
    return res.status(400).json({ error: 'Code and language are required' });
  }

  const supportedLanguages = ['cpp', 'javascript', 'python', 'java'];
  if (!supportedLanguages.includes(language)) {
    return res.status(400).json({ error: `Unsupported language. Supported languages: ${supportedLanguages.join(', ')}` });
  }

  try {
    console.log('Sending to Piston API:', { code, language, input, version: languageVersions[language] });

    const fileExtensions = {
      'cpp': 'cpp',
      'javascript': 'js',
      'python': 'py',
      'java': 'java'
    };

    const pistonResponse = await axios.post(PISTON_API_URL, {
      language,
      version: languageVersions[language],
      files: [{
        name: `main.${fileExtensions[language]}`,
        content: code
      }],
      stdin: input || '',
      args: [],
      compile_timeout: 10000,
      run_timeout: 3000
    }, {
      headers: { 'Content-Type': 'application/json' },
      httpsAgent: new https.Agent({
        rejectUnauthorized: false
      })
    });

    const { run } = pistonResponse.data;
    console.log('Piston API response:', run);

    res.json({
      output: run.stdout || '',
      error: run.stderr || (run.code !== 0 ? 'Execution failed' : '')
    });
  } catch (error) {
    console.error('Piston API error:', error.response ? error.response.data : error.message);
    const errorMessage = error.response?.data?.message || 'Failed to execute code via Piston API';
    res.status(500).json({ error: errorMessage });
  }
});

// Use Routes
app.use('/api/auth', authRoutes);
app.use('/api/files', fileRoutes);

// Global Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err.stack);
  res.status(500).json({ message: err.message || 'Something went wrong!' });
});

// Start the Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});