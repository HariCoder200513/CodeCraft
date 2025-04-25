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

const http = require('http');
const { Server } = require('socket.io');

// Room Schema
const RoomSchema = new mongoose.Schema({
  roomId: {
    type: String,
    required: true,
    unique: true
  },
  creatorId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  users: [{
    _id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    username: String
  }],
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const Room = mongoose.model('Room', RoomSchema);

const app = express();

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: 'http://localhost:4200',
    methods: ['GET', 'POST'],
    credentials: true
  }
});

io.on('connection', (socket) => {
  console.log('New client connected:', socket.id);

  socket.on('joinRoom', ({ roomId, user }) => {
    socket.join(roomId);
    io.to(roomId).emit('userJoined', { roomId, user });
  });

  socket.on('leaveRoom', async ({ roomId, userId, username }) => {
    socket.leave(roomId);
    io.to(roomId).emit('userLeft', { roomId, userId, username });
  
    // Update room in database
    try {
      const room = await Room.findOne({ roomId });
      if (room) {
        room.users = room.users.filter(u => u._id.toString() !== userId);
        await room.save();
        // Delete room if empty
        if (room.users.length === 0) {
          await Room.deleteOne({ roomId });
          console.log(`Room deleted (empty after leave): ${roomId}`);
        }
      }
    } catch (error) {
      console.error('Error updating room on leave:', error);
    }
  });

  socket.on('kickUser', ({ roomId, userId, username }) => {
    io.to(roomId).emit('userKicked', { roomId, userId, username });
  });

  socket.on('codeSaved', ({ roomId, filename, language, code }) => {
    io.to(roomId).emit('codeSaved', { roomId, filename, language, code });
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

// Middleware
app.use(cors({
  origin: 'http://localhost:4200',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
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

    // Create admin user if it doesn't exist
    const adminEmail = 'admin@codecraft.com';
    const adminExists = await User.findOne({ email: adminEmail });
    if (!adminExists) {
      const adminUser = new User({
        email: adminEmail,
        secretQuestion: 'What is your role?',
        secretAnswer: 'Admin',
        username: 'admin',
        role: 'admin',
        provider: 'local'
      });
      adminUser.password = 'Admin123'; // Set plain password, let middleware hash it
      await adminUser.save();
      console.log(`Admin user created: ${adminEmail}`);
    } else {
      console.log(`Admin user already exists: ${adminEmail}`);
    }
  } catch (error) {
    console.error(`Database connection error: ${error.message}`);
    process.exit(1);
  }
};
connectDB();

const adminAuth = async (req, res, next) => {
  const token = req.header('x-auth-token');
  if (!token) {
    console.log('No token provided');
    return res.status(401).json({ message: 'No token, authorization denied' });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log('Decoded JWT in adminAuth:', decoded);
    if (decoded.role !== 'admin') {
      console.log('Access denied: User role is not admin', decoded.role);
      return res.status(403).json({ message: 'Access denied: Admins only' });
    }
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Token verification failed:', error.message);
    res.status(401).json({ message: 'Token is not valid' });
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
    console.log('Hashed password:', this.password);
  }
  if (this.isModified('secretAnswer') && this.secretAnswer) {
    const salt = await bcrypt.genSalt(10);
    this.secretAnswer = await bcrypt.hash(this.secretAnswer, salt);
    console.log('Hashed secretAnswer:', this.secretAnswer);
  }
  console.log('Saving user:', {
    email: this.email,
    password: this.isModified('password') ? '[hashed]' : this.password,
    secretQuestion: this.secretQuestion,
    secretAnswer: this.isModified('secretAnswer') ? '[hashed]' : this.secretAnswer
  });
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
        const randomPassword = Math.random().toString(36).slice(-8);
        const randomSecretAnswer = Math.random().toString(36).slice(-8);
        user = new User({
          providerId: profile.id,
          provider: 'github',
          email: profile.emails && profile.emails[0]?.value ? profile.emails[0].value : `${profile.id}@githubuser.com`,
          username: profile.username,
          password: randomPassword,
          secretQuestion: 'Default question for GitHub users',
          secretAnswer: randomSecretAnswer
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
    console.log('Signup attempt:', { email, password, secretQuestion, secretAnswer });
    if (!email || !password || !secretQuestion || !secretAnswer) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    let user = await User.findOne({ email });
    if (user) {
      console.log('User already exists:', email);
      return res.status(400).json({ message: 'User already exists' });
    }
    user = new User({
      email,
      password,
      secretQuestion,
      secretAnswer,
      provider: 'local',
      username: email.split('@')[0],
      role: 'user' // Default role for new users
    });
    await user.save();
    console.log('User signed up:', { email, username: user.username, role: user.role });
    const token = jwt.sign(
      { _id: user._id, email: user.email, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.json({ token });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ message: 'Signup failed: ' + error.message });
  }
});

authRoutes.get('/users', adminAuth, async (req, res) => {
  try {
    const adminId = req.user._id;
    const users = await User.find({ _id: { $ne: adminId } }).select('email username role createdAt');
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Failed to fetch users: ' + error.message });
  }
});

authRoutes.delete('/users/:userId', adminAuth, async (req, res) => {
  try {
    const userId = req.params.userId;
    const adminId = req.user._id;

    if (userId === adminId.toString()) {
      console.log('Admin attempted to delete own account:', adminId);
      return res.status(400).json({ message: 'Cannot delete your own admin account' });
    }

    // Find and delete the user
    const user = await User.findByIdAndDelete(userId);
    if (!user) {
      console.log('User not found for deletion:', userId);
      return res.status(404).json({ message: 'User not found' });
    }

    // Delete all files associated with the user
    const fileDeletionResult = await File.deleteMany({ userId });
    console.log(`Deleted ${fileDeletionResult.deletedCount} files for user: ${user.email}`);

    console.log(`User deleted by admin: ${user.email}`);
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ message: 'Failed to delete user: ' + error.message });
  }
});

authRoutes.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log('Login attempt:', { email, password });
    if (!email || !password) {
      console.log('Missing email or password:', { email, password });
      return res.status(400).json({ message: 'Email and password are required' });
    }
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      console.log('User not found:', email);
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    if (!user.password) {
      console.log('User has no password set:', email);
      return res.status(400).json({ message: 'User account is corrupted. Please reset your password.' });
    }
    const isPasswordMatch = await bcrypt.compare(password, user.password);
    console.log('Password match result:', isPasswordMatch);
    if (!isPasswordMatch) {
      console.log('Password mismatch for:', email);
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    console.log('Login successful:', email);
    const token = jwt.sign(
      { _id: user._id, email: user.email, username: user.username || email.split('@')[0], role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.json({ token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Login failed: ' + error.message });
  }
});

authRoutes.post('/forgot-password', async (req, res) => {
  try {
    const { email, secretQuestion, secretAnswer } = req.body;
    console.log('Forgot password attempt:', { email, secretQuestion, secretAnswer });
    if (!email || !secretQuestion || !secretAnswer) {
      console.log('Missing fields:', { email, secretQuestion, secretAnswer });
      return res.status(400).json({ message: 'All fields are required' });
    }
    const user = await User.findOne({ email }).select('+secretAnswer');
    if (!user) {
      console.log('User not found:', email);
      return res.status(400).json({ message: 'User not found' });
    }
    if (user.secretQuestion !== secretQuestion) {
      console.log('Secret question mismatch:', { input: secretQuestion, stored: user.secretQuestion });
      return res.status(400).json({ message: 'Invalid secret question' });
    }
    const isAnswerMatch = await bcrypt.compare(secretAnswer, user.secretAnswer);
    console.log('Secret answer match result:', isAnswerMatch);
    if (!isAnswerMatch) {
      console.log('Secret answer mismatch for:', email);
      return res.status(400).json({ message: 'Invalid secret answer' });
    }
    console.log('Secret answer verified for:', email);
    res.json({ message: 'Secret answer verified. Please proceed to reset your password.', email });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ message: 'Password retrieval failed: ' + error.message });
  }
});

authRoutes.post('/reset-password', async (req, res) => {
  try {
    const { email, newPassword } = req.body;
    console.log('Reset password attempt:', { email, newPassword });
    if (!email || !newPassword) {
      console.log('Missing email or newPassword:', { email, newPassword });
      return res.status(400).json({ message: 'Email and new password are required' });
    }
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      console.log('User not found:', email);
      return res.status(400).json({ message: 'User not found' });
    }
    user.password = newPassword;
    await user.save();
    console.log('Password reset successful:', { email });
    const updatedUser = await User.findOne({ email }).select('+password');
    console.log('Verified updated user:', {
      email: updatedUser.email,
      password: updatedUser.password ? '[hashed]' : 'undefined'
    });
    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ message: 'Password reset failed: ' + error.message });
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
        { _id: req.user._id, email: req.user.email, username: req.user.username, role: req.user.role },
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

fileRoutes.get('/user/:userId', adminAuth, async (req, res) => {
  try {
    const userId = req.params.userId;
    const files = await File.find({ userId }).sort({ updatedAt: -1 });
    res.json(files);
  } catch (error) {
    console.error('Error fetching user files:', error);
    res.status(500).json({ message: 'Failed to fetch user files: ' + error.message });
  }
});

fileRoutes.delete('/admin/delete/:fileId', adminAuth, async (req, res) => {
  try {
    const fileId = req.params.fileId;
    const file = await File.findByIdAndDelete(fileId);
    if (!file) {
      return res.status(404).json({ message: 'File not found' });
    }
    console.log(`File deleted by admin: ${file.filename} (ID: ${fileId})`);
    res.json({ message: 'File deleted successfully' });
  } catch (error) {
    console.error('Error deleting file by admin:', error);
    res.status(500).json({ message: 'Failed to delete file: ' + error.message });
  }
});


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

fileRoutes.delete('/delete/:fileId', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const fileId = req.params.fileId;
    console.log('Delete file attempt:', { fileId, userId });

    const file = await File.findOneAndDelete({ _id: fileId, userId });
    if (!file) {
      console.log('File not found or not authorized:', { fileId, userId });
      return res.status(404).json({ message: 'File not found or not authorized' });
    }

    console.log('File deleted successfully:', { fileId, filename: file.filename });
    res.json({ message: 'File deleted successfully' });
  } catch (error) {
    console.error('Error deleting file:', error);
    res.status(500).json({ message: 'Failed to delete file: ' + error.message });
  }
});

const roomRoutes = express.Router();
const { v4: uuidv4 } = require('uuid');

roomRoutes.post('/create', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const roomId = uuidv4();
    const room = new Room({
      roomId,
      creatorId: userId,
      users: [{ _id: userId, username: req.user.username || req.user.email.split('@')[0] }]
    });
    await room.save();
    console.log(`Room created: ${roomId} by user: ${userId}`);
    res.json({ roomId });
  } catch (error) {
    console.error('Error creating room:', error);
    res.status(500).json({ message: 'Failed to create room: ' + error.message });
  }
});

roomRoutes.post('/join', auth, async (req, res) => {
  try {
    const { roomId } = req.body;
    const userId = req.user._id;
    const username = req.user.username || req.user.email.split('@')[0];

    if (!roomId) {
      return res.status(400).json({ message: 'Room ID is required' });
    }

    const room = await Room.findOne({ roomId });
    if (!room) {
      return res.status(404).json({ message: 'Room not found' });
    }

    if (room.users.some(u => u._id.toString() === userId)) {
      return res.status(400).json({ message: 'User already in room' });
    }

    room.users.push({ _id: userId, username });
    await room.save();
    console.log(`User ${userId} joined room: ${roomId}`);
    res.json({ room });
  } catch (error) {
    console.error('Error joining room:', error);
    res.status(500).json({ message: 'Failed to join room: ' + error.message });
  }
});

roomRoutes.post('/kick', auth, async (req, res) => {
  try {
    const { roomId, userId } = req.body;
    const creatorId = req.user._id;

    if (!roomId || !userId) {
      return res.status(400).json({ message: 'Room ID and user ID are required' });
    }

    const room = await Room.findOne({ roomId });
    if (!room) {
      return res.status(404).json({ message: 'Room not found' });
    }

    if (room.creatorId.toString() !== creatorId) {
      return res.status(403).json({ message: 'Only the room creator can kick users' });
    }

    if (!room.users.some(u => u._id.toString() === userId)) {
      return res.status(400).json({ message: 'User not in room' });
    }

    room.users = room.users.filter(u => u._id.toString() !== userId);
    await room.save();

    // Delete room if empty
    if (room.users.length === 0) {
      await Room.deleteOne({ roomId });
      console.log(`Room deleted (empty after kick): ${roomId}`);
    }

    console.log(`User ${userId} kicked from room: ${roomId}`);
    res.json({ message: 'User kicked successfully' });
  } catch (error) {
    console.error('Error kicking user:', error);
    res.status(500).json({ message: 'Failed to kick user: ' + error.message });
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
app.use('/api/rooms', roomRoutes);

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});