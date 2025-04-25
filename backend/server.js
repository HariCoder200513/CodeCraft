// Import required modules
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const passport = require('passport');
const GitHubStrategy = require('passport-github2').Strategy;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const https = require('https');
const { Server } = require('socket.io');
const http = require('http');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

// Validate environment variables
const requiredEnvVars = ['MONGODB_URI', 'JWT_SECRET', 'GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET'];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`Missing required environment variable: ${envVar}`);
    process.exit(1);
  }
}

// Initialize Express app and HTTP server
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: ['http://localhost:4200'],
    methods: ['GET', 'POST'],
    credentials: true
  }
});

// Data structures for room and user management
const rooms = new Map(); // Map<roomId, { code: string, language: string, filename: string }>
const users = new Map(); // Map<roomId, Map<socketId, { id: string, email: string, username: string, color: string }>

// Utility function to generate random color for user cursors
function getRandomColor() {
  const letters = '0123456789ABCDEF';
  let color = '#';
  for (let i = 0; i < 6; i++) {
    color += letters[Math.floor(Math.random() * 16)];
  }
  return color;
}

// Middleware setup
app.use(cors({
  origin: ['http://localhost:4200'],
  credentials: true
}));
app.use(express.json());
app.use(passport.initialize());

// MongoDB connection with retry logic
const connectDB = async () => {
  let retries = 5;
  while (retries > 0) {
    try {
      const conn = await mongoose.connect(process.env.MONGODB_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      });
      console.log(`MongoDB Connected: ${conn.connection.host}`);

      // Create admin user if it doesn't exist
      const adminEmail = 'admin@codecraft.com';
      const adminExists = await User.findOne({ email: adminEmail });
      if (!adminExists) {
        const hashedPassword = await bcrypt.hash('Admin123', 10);
        const adminUser = new User({
          email: adminEmail,
          password: hashedPassword,
          secretQuestion: 'What is your role?',
          secretAnswer: 'Admin',
          username: 'admin',
          role: 'admin',
          provider: 'local'
        });
        await adminUser.save();
        console.log(`Admin user created: ${adminEmail}`);
      } else {
        console.log(`Admin user already exists: ${adminEmail}`);
      }
      return;
    } catch (error) {
      console.error(`Database connection error: ${error.message}`);
      retries -= 1;
      if (retries === 0) {
        console.error('Max retries reached. Exiting...');
        process.exit(1);
      }
      console.log(`Retrying connection (${retries} attempts left)...`);
      await new Promise(resolve => setTimeout(resolve, 5000));
    }
  }
};

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
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Bcrypt pre-save middleware for hashing password and secretAnswer
UserSchema.pre('save', async function(next) {
  if (this.isModified('password') && this.password) {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    console.log('Hashed password for user:', this.email);
  }
  if (this.isModified('secretAnswer') && this.secretAnswer) {
    const salt = await bcrypt.genSalt(10);
    this.secretAnswer = await bcrypt.hash(this.secretAnswer, salt);
    console.log('Hashed secretAnswer for user:', this.email);
  }
  next();
});

const User = mongoose.model('User', UserSchema);

// File Schema
const fileSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  filename: { type: String, required: true },
  language: { type: String, required: true },
  code: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const File = mongoose.model('File', fileSchema);

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
        const randomPassword = Math.random().toString(36).slice(-8);
        const randomSecretAnswer = Math.random().toString(36).slice(-8);
        user = new User({
          providerId: profile.id,
          provider: 'github',
          email: profile.emails && profile.emails[0]?.value ? profile.emails[0].value : `${profile.id}@githubuser.com`,
          username: profile.username || `github_${profile.id}`,
          password: randomPassword,
          secretQuestion: 'Default question for GitHub users',
          secretAnswer: randomSecretAnswer,
          role: 'user'
        });
      } else {
        user.providerId = profile.id;
        user.provider = 'github';
        user.username = profile.username || user.username || user.email.split('@')[0];
      }
      await user.save();
    }
    
    return done(null, user);
  } catch (err) {
    console.error('GitHub Strategy error:', err);
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

// Admin Authentication Middleware
const adminAuth = async (req, res, next) => {
  const token = req.header('x-auth-token');
  if (!token) {
    return res.status(401).json({ message: 'No token, authorization denied' });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'admin') {
      return res.status(403).json({ message: 'Access denied: Admins only' });
    }
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Token is not valid' });
  }
};

// Socket.IO Authentication Middleware
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) {
    return next(new Error('Authentication error: No token provided'));
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    socket.user = { id: decoded.id, email: decoded.email, username: decoded.email.split('@')[0] };
    next();
  } catch (error) {
    next(new Error('Authentication error: Invalid token'));
  }
});

// Socket.IO Event Handlers
io.on('connection', (socket) => {
  console.log(`User ${socket.user.email} connected`);

  socket.on('createRoom', (data) => {
    const token = data.token;
    if (!token || token !== socket.handshake.auth.token) {
      socket.emit('error', { message: 'Invalid token' });
      return;
    }
    const roomId = uuidv4();
    rooms.set(roomId, { code: '', language: 'cpp', filename: '' });
    socket.emit('roomCreated', { roomId });
    console.log(`Room created: ${roomId} by user ${socket.user.email}`);
  });

  socket.on('joinRoom', (data) => {
    const { roomId, token } = data;
    if (!token || token !== socket.handshake.auth.token) {
      socket.emit('error', { message: 'Invalid token' });
      return;
    }
    if (!roomId) {
      socket.emit('error', { message: 'Room ID is required' });
      return;
    }
    socket.join(roomId);
    if (!rooms.has(roomId)) {
      rooms.set(roomId, {
        code: '',
        language: 'cpp',
        filename: 'main.cpp'
      });
    }
    if (!users.has(roomId)) {
      users.set(roomId, new Map());
    }
    const userColor = getRandomColor();
    users.get(roomId).set(socket.id, {
      id: socket.user.id,
      email: socket.user.email,
      username: socket.user.username,
      color: userColor
    });
    const userList = Array.from(users.get(roomId).values());
    io.to(roomId).emit('userListUpdate', { users: userList });
    const room = rooms.get(roomId);
    socket.emit('roomJoined', {
      roomId,
      code: room.code,
      language: room.language,
      filename: room.filename
    });
    console.log(`User ${socket.user.email} joined room: ${roomId}`);
  });

  socket.on('leaveRoom', (data) => {
    const { roomId, token } = data;
    if (!token || token !== socket.handshake.auth.token) {
      socket.emit('error', { message: 'Invalid token' });
      return;
    }
    if (!roomId || !rooms.has(roomId)) {
      socket.emit('error', { message: 'Invalid room' });
      return;
    }
    socket.leave(roomId);
    if (users.has(roomId)) {
      users.get(roomId).delete(socket.id);
      const userList = Array.from(users.get(roomId).values());
      io.to(roomId).emit('userListUpdate', { users: userList });
    }
    if (io.sockets.adapter.rooms.get(roomId)?.size === 0) {
      rooms.delete(roomId);
      users.delete(roomId);
      console.log(`Room ${roomId} deleted (no users remaining)`);
    }
    console.log(`User ${socket.user.email} left room: ${roomId}`);
  });

  socket.on('codeChange', (data) => {
    const { roomId, code, token } = data;
    if (!token || token !== socket.handshake.auth.token) {
      socket.emit('error', { message: 'Invalid token' });
      return;
    }
    if (!rooms.has(roomId)) {
      socket.emit('error', { message: 'Invalid room' });
      return;
    }
    rooms.set(roomId, { ...rooms.get(roomId), code });
    socket.to(roomId).emit('codeChange', { code });
    console.log(`Code updated in room ${roomId} by ${socket.user.email}`);
  });

  socket.on('languageChange', (data) => {
    const { roomId, language, code, token } = data;
    if (!token || token !== socket.handshake.auth.token) {
      socket.emit('error', { message: 'Invalid token' });
      return;
    }
    if (!rooms.has(roomId)) {
      socket.emit('error', { message: 'Invalid room' });
      return;
    }
    rooms.set(roomId, { code, language, filename: '' });
    socket.to(roomId).emit('languageChange', { language, code });
    console.log(`Language changed to ${language} in room ${roomId} by ${socket.user.email}`);
  });

  socket.on('cursorUpdate', (data) => {
    const { roomId, position, token } = data;
    if (!token || token !== socket.handshake.auth.token) {
      socket.emit('error', { message: 'Invalid token' });
      return;
    }
    if (!rooms.has(roomId) || !users.has(roomId) || !users.get(roomId).has(socket.id)) {
      socket.emit('error', { message: 'Invalid room or user' });
      return;
    }
    const user = users.get(roomId).get(socket.id);
    socket.to(roomId).emit('cursorUpdate', {
      userId: socket.user.id,
      username: user.username,
      color: user.color,
      position
    });
    console.log(`Cursor updated in room ${roomId} by ${socket.user.email}`);
  });

  socket.on('runCode', async (data) => {
    const { roomId, code, language, input, token } = data;
    if (!token || token !== socket.handshake.auth.token) {
      socket.emit('error', { message: 'Invalid token' });
      return;
    }
    if (!rooms.has(roomId)) {
      socket.emit('error', { message: 'Invalid room' });
      return;
    }
    try {
      io.to(roomId).emit('codeRunning', { isRunning: true });
      const result = await runCode(code, language, input);
      io.to(roomId).emit('runCodeResult', result);
      io.to(roomId).emit('codeRunning', { isRunning: false });
      console.log(`Code executed in room ${roomId} by ${socket.user.email}`);
    } catch (error) {
      io.to(roomId).emit('runCodeResult', { output: '', error: error.message || 'Failed to run code' });
      io.to(roomId).emit('codeRunning', { isRunning: false });
      console.error(`Code execution failed in room ${roomId}: ${error.message}`);
    }
  });

  socket.on('saveCode', async (data) => {
    const { roomId, filename, language, code, token } = data;
    if (!token || token !== socket.handshake.auth.token) {
      socket.emit('error', { message: 'Invalid token' });
      return;
    }
    if (!rooms.has(roomId) || !filename) {
      socket.emit('error', { message: 'Invalid room or filename' });
      return;
    }
    try {
      if (!socket.user || !socket.user.id) {
        socket.emit('error', { message: 'User authentication failed' });
        return;
      }
      let file = await File.findOne({ userId: socket.user.id, filename });
      if (file) {
        file.code = code;
        file.language = language;
        file.updatedAt = new Date();
      } else {
        file = new File({
          userId: socket.user.id,
          filename,
          language,
          code,
          createdAt: new Date(),
          updatedAt: new Date()
        });
      }
      await file.save();
      rooms.set(roomId, { ...rooms.get(roomId), filename });
      io.to(roomId).emit('fileSaved', { file, message: 'File saved successfully' });
      console.log(`File saved: ${filename} by ${socket.user.email} in room ${roomId}`);
    } catch (error) {
      socket.emit('error', { message: error.message || 'Error saving file' });
      console.error(`File save failed for ${socket.user.email}: ${error.message}`);
    }
  });

  socket.on('deleteFile', async (data) => {
    const { roomId, fileId, token } = data;
    if (!token || token !== socket.handshake.auth.token) {
      socket.emit('error', { message: 'Invalid token' });
      return;
    }
    if (!rooms.has(roomId)) {
      socket.emit('error', { message: 'Invalid room' });
      return;
    }
    try {
      if (!socket.user || !socket.user.id) {
        socket.emit('error', { message: 'User authentication failed' });
        return;
      }
      const file = await File.findOne({ _id: fileId, userId: socket.user.id });
      if (!file) {
        socket.emit('error', { message: 'File not found or unauthorized' });
        return;
      }
      await File.deleteOne({ _id: fileId });
      io.to(roomId).emit('fileDeleted', { fileId });
      console.log(`File deleted: ${fileId} by ${socket.user.email} in room ${roomId}`);
    } catch (error) {
      socket.emit('error', { message: error.message || 'Error deleting file' });
      console.error(`File deletion failed for ${socket.user.email}: ${error.message}`);
    }
  });

  socket.on('disconnect', () => {
    for (const [roomId, roomUsers] of users) {
      if (roomUsers.has(socket.id)) {
        roomUsers.delete(socket.id);
        const userList = Array.from(roomUsers.values());
        io.to(roomId).emit('userListUpdate', { users: userList });
        if (io.sockets.adapter.rooms.get(roomId)?.size === 0) {
          rooms.delete(roomId);
          users.delete(roomId);
          console.log(`Room ${roomId} deleted (no users remaining)`);
        }
      }
    }
    console.log(`User ${socket.user.email} disconnected`);
  });
});

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
      username: email.split('@')[0],
      role: 'user'
    });
    await user.save();
    const token = jwt.sign(
      { id: user._id, email: user.email, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.json({ token });
    console.log(`User signed up: ${email}`);
  } catch (error) {
    res.status(500).json({ message: 'Signup failed: ' + error.message });
    console.error(`Signup error for ${req.body.email}: ${error.message}`);
  }
});

authRoutes.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    if (user.provider === 'github') {
      return res.status(400).json({ message: 'Please log in using GitHub' });
    }
    if (!user.password) {
      return res.status(400).json({ message: 'Account issue: No password set' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign(
      { id: user._id, email: user.email, username: user.username || email.split('@')[0], role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.json({ token });
    console.log(`User logged in: ${email}`);
  } catch (error) {
    res.status(500).json({ message: 'Login failed: ' + error.message });
    console.error(`Login error for ${req.body.email}: ${error.message}`);
  }
});

authRoutes.post('/forgot-password', async (req, res) => {
  try {
    const { email, secretQuestion, secretAnswer } = req.body;
    if (!email || !secretQuestion || !secretAnswer) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    const user = await User.findOne({ email }).select('+secretAnswer');
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }
    if (user.secretQuestion !== secretQuestion) {
      return res.status(400).json({ message: 'Invalid secret question' });
    }
    const isAnswerMatch = await bcrypt.compare(secretAnswer, user.secretAnswer);
    if (!isAnswerMatch) {
      return res.status(400).json({ message: 'Invalid secret answer' });
    }
    res.json({ message: 'Secret answer verified', email });
    console.log(`Secret answer verified for: ${email}`);
  } catch (error) {
    res.status(500).json({ message: 'Password retrieval failed: ' + error.message });
    console.error(`Forgot password error for ${req.body.email}: ${error.message}`);
  }
});

authRoutes.post('/reset-password', async (req, res) => {
  try {
    const { email, newPassword } = req.body;
    if (!email || !newPassword) {
      return res.status(400).json({ message: 'Email and new password are required' });
    }
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }
    user.password = newPassword;
    await user.save();
    res.json({ message: 'Password reset successfully' });
    console.log(`Password reset for: ${email}`);
  } catch (error) {
    res.status(500).json({ message: 'Password reset failed: ' + error.message });
    console.error(`Reset password error for ${req.body.email}: ${error.message}`);
  }
});

authRoutes.get('/github', passport.authenticate('github', { scope: ['user', 'user:email'] }));

authRoutes.get('/github/callback',
  passport.authenticate('github', { session: false }),
  (req, res) => {
    try {
      if (!req.user) {
        res.redirect('http://localhost:4200/auth/callback?error=GitHub authentication failed');
        return;
      }
      const token = jwt.sign(
        { id: req.user._id, email: req.user.email, username: req.user.username, role: req.user.role },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
      res.redirect(`http://localhost:4200/auth/callback?token=${token}`);
      console.log(`GitHub login successful for: ${req.user.email}`);
    } catch (error) {
      res.redirect(`http://localhost:4200/auth/callback?error=${encodeURIComponent(error.message || 'GitHub callback error')}`);
      console.error(`GitHub callback error for ${req.user?.email || 'unknown'}: ${error.message}`);
    }
  }
);

authRoutes.get('/users', adminAuth, async (req, res) => {
  try {
    const adminId = req.user.id;
    const users = await User.find({ _id: { $ne: adminId } }).select('email username role createdAt');
    res.json(users);
    console.log(`Users fetched by admin: ${req.user.email}`);
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch users: ' + error.message });
    console.error(`Error fetching users for admin ${req.user.email}: ${error.message}`);
  }
});

authRoutes.delete('/users/:userId', adminAuth, async (req, res) => {
  try {
    const userId = req.params.userId;
    const adminId = req.user.id;
    if (userId === adminId) {
      return res.status(400).json({ message: 'Cannot delete your own admin account' });
    }
    const user = await User.findByIdAndDelete(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    await File.deleteMany({ userId });
    res.json({ message: 'User deleted successfully' });
    console.log(`User ${user.email} deleted by admin: ${req.user.email}`);
  } catch (error) {
    res.status(500).json({ message: 'Failed to delete user: ' + error.message });
    console.error(`Error deleting user by admin ${req.user.email}: ${error.message}`);
  }
});

// File Routes
const fileRoutes = express.Router();

fileRoutes.post('/save', auth, async (req, res) => {
  try {
    const { filename, language, code, fileId } = req.body;
    const userId = req.user.id;
    if (!filename || !language || !code) {
      return res.status(400).json({ message: 'Filename, language, and code are required' });
    }
    if (fileId) {
      const file = await File.findOneAndUpdate(
        { _id: fileId, userId },
        { filename, language, code, updatedAt: new Date() },
        { new: true }
      );
      if (!file) {
        return res.status(404).json({ message: 'File not found or not authorized' });
      }
      res.json({ fileId: file._id, message: 'File updated successfully' });
      console.log(`File updated: ${filename} by ${req.user.email}`);
    } else {
      const file = new File({ userId, filename, language, code });
      await file.save();
      res.json({ fileId: file._id, message: 'File saved successfully' });
      console.log(`File saved: ${filename} by ${req.user.email}`);
    }
  } catch (error) {
    res.status(500).json({ message: 'Failed to save file: ' + error.message });
    console.error(`Error saving file for ${req.user.email}: ${error.message}`);
  }
});

fileRoutes.get('/list', auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const files = await File.find({ userId }).sort({ updatedAt: -1 });
    res.json(files);
    console.log(`Files fetched for: ${req.user.email}`);
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch files: ' + error.message });
    console.error(`Error fetching files for ${req.user.email}: ${error.message}`);
  }
});

fileRoutes.get('/:fileId', auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const file = await File.findOne({ _id: req.params.fileId, userId });
    if (!file) {
      return res.status(404).json({ message: 'File not found or not authorized' });
    }
    res.json(file);
    console.log(`File ${req.params.fileId} fetched for: ${req.user.email}`);
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch file: ' + error.message });
    console.error(`Error fetching file ${req.params.fileId} for ${req.user.email}: ${error.message}`);
  }
});

fileRoutes.delete('/delete/:fileId', auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const fileId = req.params.fileId;
    const file = await File.findOneAndDelete({ _id: fileId, userId });
    if (!file) {
      return res.status(404).json({ message: 'File not found or not authorized' });
    }
    res.json({ message: 'File deleted successfully' });
    console.log(`File ${fileId} deleted by: ${req.user.email}`);
  } catch (error) {
    res.status(500).json({ message: 'Failed to delete file: ' + error.message });
    console.error(`Error deleting file ${req.params.fileId} for ${req.user.email}: ${error.message}`);
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
    console.error('Failed to fetch Piston runtimes:', error.message);
  }
}

async function runCode(code, language, input) {
  try {
    const config = {
      cpp: { language: 'cpp', version: '10.2.0', extension: 'cpp' },
      javascript: { language: 'javascript', version: '18.15.0', extension: 'js' },
      python: { language: 'python', version: '3.10.0', extension: 'py' },
      java: { language: 'java', version: '15.0.2', extension: 'java' }
    }[language];
    if (!config) {
      throw new Error('Unsupported language');
    }
    const response = await axios.post(PISTON_API_URL, {
      language: config.language,
      version: config.version,
      files: [{ name: `main.${config.extension}`, content: code }],
      stdin: input || '',
      args: [],
      compile_timeout: 10000,
      run_timeout: 3000
    }, {
      httpsAgent: new https.Agent({ rejectUnauthorized: false })
    });
    const result = response.data.run;
    return {
      output: result.stdout || '',
      error: result.stderr || (result.code !== 0 ? 'Execution failed' : '')
    };
  } catch (error) {
    throw new Error(error.response?.data?.message || 'Failed to run code');
  }
}

// Code Execution Endpoint
app.post('/api/run', auth, async (req, res) => {
  try {
    const { code, language, input } = req.body;
    if (!code || !language) {
      return res.status(400).json({ error: 'Code and language are required' });
    }
    const supportedLanguages = ['cpp', 'javascript', 'python', 'java'];
    if (!supportedLanguages.includes(language)) {
      return res.status(400).json({ error: `Unsupported language: ${language}` });
    }
    const result = await runCode(code, language, input);
    res.json(result);
    console.log(`Code executed by: ${req.user.email}`);
  } catch (error) {
    res.status(500).json({ error: error.message || 'Failed to execute code' });
    console.error(`Code execution error for ${req.user.email}: ${error.message}`);
  }
});

// Health Check Endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
  console.log('Health check accessed');
});

// Use Routes
app.use('/api/auth', authRoutes);
app.use('/api/files', fileRoutes);

// Global Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err.stack);
  res.status(500).json({ message: err.message || 'Something went wrong!' });
});

// Initialize Database and Start Server
const PORT = process.env.PORT || 5000;
const startServer = async () => {
  await connectDB();
  await fetchLanguageVersions();
  server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
};

startServer();