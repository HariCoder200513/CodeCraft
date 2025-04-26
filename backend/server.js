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
const { v4: uuidv4 } = require('uuid');

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

// File Schema (assuming it was defined elsewhere but not shown)
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

// User Schema (assuming it was defined elsewhere but not shown)
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
      adminUser.password = 'Admin123';
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

// Socket Authentication Middleware
const socketAuth = (socket, next) => {
  const token = socket.handshake.query.token;
  if (!token) {
    console.log('No token provided in socket handshake');
    return next(new Error('Authentication error: No token provided'));
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    socket.user = decoded;
    next();
  } catch (error) {
    console.log('Token verification failed:', error.message);
    next(new Error('Authentication error: Invalid token'));
  }
};

// Apply socket authentication
io.use(socketAuth);

io.on('connection', (socket) => {
  console.log('New client connected:', socket.id);

  socket.on('joinRoom', async ({ roomId, user }) => {
    if (!socket.user || !socket.user._id) {
      return socket.emit('error', { message: 'Authentication required to join room' });
    }
    const userId = socket.user._id;
    const username = socket.user.username || socket.user.email.split('@')[0];
    
    try {
      const room = await Room.findOne({ roomId });
      if (!room) {
        return socket.emit('error', { message: 'Room not found' });
      }
  
      // Prevent duplicate entries
      if (!room.users.some(u => u._id.toString() === userId)) {
        room.users.push({ _id: userId, username });
        await room.save();
      }
  
      socket.join(roomId);
      // Broadcast the updated user list to all clients in the room
      io.to(roomId).emit('userJoined', { roomId, users: room.users });
    } catch (err) {
      console.error('Error updating room on join:', err);
      socket.emit('error', { message: 'Failed to join room' });
    }
  });

  socket.on('leaveRoom', async ({ roomId }) => {
    if (!socket.user || !socket.user._id) {
      return socket.emit('error', { message: 'Authentication required to leave room' });
    }
    const userId = socket.user._id;
    const username = socket.user.username || socket.user.email.split('@')[0];
  
    try {
      const room = await Room.findOne({ roomId });
      if (room) {
        room.users = room.users.filter(u => u._id.toString() !== userId);
        await room.save();
  
        socket.leave(roomId);
        io.to(roomId).emit('userLeft', { roomId, userId, username, users: room.users });
  
        if (room.users.length === 0) {
          await Room.deleteOne({ roomId });
          console.log(`Room deleted (empty after leave): ${roomId}`);
        }
      }
    } catch (err) {
      console.error('Error updating room on leave:', err);
    }
  });

  socket.on('kickUser', ({ roomId, userId }) => {
    if (!socket.user || !socket.user._id) {
      return socket.emit('error', { message: 'Authentication required to kick user' });
    }
    const creatorId = socket.user._id;
    Room.findOne({ roomId, creatorId }).then(room => {
      if (!room) {
        return socket.emit('error', { message: 'Only room creator can kick users' });
      }
      const username = room.users.find(u => u._id.toString() === userId)?.username || 'User';
      Room.findOneAndUpdate(
        { roomId },
        { $pull: { users: { _id: userId } } }
      ).then(() => {
        io.to(roomId).emit('userKicked', { roomId, userId, username });
        if (room.users.length === 0) {
          Room.deleteOne({ roomId }).then(() => {
            console.log(`Room deleted (empty after kick): ${roomId}`);
          });
        }
      }).catch(err => {
        console.error('Error kicking user:', err);
        socket.emit('error', { message: 'Failed to kick user' });
      });
    });
  });

  socket.on('checkFileExists', async ({ roomId, filename }, callback) => {
    if (!socket.user || !socket.user._id) {
      return callback({ error: 'Authentication required to check file existence' });
    }
    try {
      const room = await Room.findOne({ roomId });
      if (!room) {
        return callback(false);
      }
      const users = room.users || [];
      const existingFiles = await File.find({ filename, userId: { $in: users.map(u => u._id) } });
      callback(existingFiles.length > 0);
    } catch (error) {
      console.error('Error checking file existence:', error);
      callback(false);
    }
  });

  socket.on('shareCode', async (data) => {
    if (!socket.user || !socket.user._id) {
      return socket.emit('error', { message: 'Authentication required to share code' });
    }
    const { roomId, fileId, filename, language, code, userId: clientUserId, username: clientUsername, overwrite } = data;
    const userId = socket.user._id;
    const username = socket.user.username || socket.user.email.split('@')[0];
  
    if (userId !== clientUserId) {
      console.log(`User ID mismatch: socket.user._id=${userId}, clientUserId=${clientUserId}`);
      return socket.emit('error', { message: 'User ID mismatch, authentication failed' });
    }
  
    try {
      const room = await Room.findOne({ roomId });
      if (!room) {
        return socket.emit('error', { message: 'Room not found' });
      }
  
      let savedFile = await File.findById(fileId);
      if (!savedFile || savedFile.userId.toString() !== userId) {
        return socket.emit('error', { message: 'File not found or not authorized' });
      }
  
      if (overwrite) {
        // Update the existing file for the owner
        savedFile = await File.findOneAndUpdate(
          { _id: fileId, userId },
          { language, code, updatedAt: Date.now() },
          { new: true }
        );
      }
  
      // Broadcast the shared code to all users in the room
      io.to(roomId).emit('codeShared', {
        fileId: savedFile._id,
        filename: savedFile.filename, // Use the original filename
        language: savedFile.language,
        code: savedFile.code,
        userId,
        username,
        message: overwrite ? `${username} updated shared code` : `${username} shared new code`
      });
  
    } catch (error) {
      console.error('Error sharing code:', error);
      socket.emit('error', { message: 'Failed to share code' });
    }
  });

  socket.on('codeSaved', ({ roomId, fileId, filename, language, code, userId, username }) => {
    if (!socket.user || !socket.user._id) {
      return socket.emit('error', { message: 'Authentication required to save code' });
    }
    if (socket.user._id !== userId) {
      return socket.emit('error', { message: 'User ID mismatch, authentication failed' });
    }
    io.to(roomId).emit('codeSaved', { roomId, fileId, filename, language, code, userId, username });
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

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
      { _id: user._id, email: user.email, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' } // Changed from '1h' to '24h'
    );
    res.json({ token });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ message: 'Signup failed: ' + error.message });
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
    if (!user.password) {
      return res.status(400).json({ message: 'User account is corrupted. Please reset your password.' });
    }
    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (!isPasswordMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign(
      { _id: user._id, email: user.email, username: user.username || email.split('@')[0], role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' } // Changed from '1h' to '24h'
    );
    res.json({ token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Login failed: ' + error.message });
  }
});

authRoutes.get('/github', passport.authenticate('github', { scope: ['user', 'user:email'] }));

authRoutes.get('/github/callback',
  passport.authenticate('github', { session: false }),
  (req, res) => {
    try {
      if (!req.user) {
        return res.redirect('http://localhost:4200/auth/callback?error=GitHub authentication failed: No user found');
      }
      const token = jwt.sign(
        { _id: req.user._id, email: req.user.email, username: req.user.username, role: req.user.role },
        process.env.JWT_SECRET,
        { expiresIn: '24h' } // Changed from '1h' to '24h'
      );
      res.redirect(`http://localhost:4200/auth/callback?token=${token}`);
    } catch (error) {
      res.redirect(`http://localhost:4200/auth/callback?error=${encodeURIComponent(error.message || 'GitHub callback error')}`);
    }
  }
);

// File Routes
const fileRoutes = express.Router();

fileRoutes.post('/save', auth, async (req, res) => {
  try {
    const { fileId, filename, language, code } = req.body;
    const userId = req.user._id;

    if (!filename || !language || !code) {
      return res.status(400).json({ message: 'Filename, language, and code are required' });
    }

    let savedFile;
    let isUpdate = false;

    if (fileId) {
      // Check if the user is authorized to update this file (either owner or in the same room)
      savedFile = await File.findById(fileId);
      if (!savedFile) {
        return res.status(404).json({ message: 'File not found' });
      }

      const room = await Room.findOne({ 
        roomId: { $in: (await Room.find({ users: { $elemMatch: { _id: userId } } })).map(r => r.roomId) },
        users: { $elemMatch: { _id: savedFile.userId } }
      });
      if (savedFile.userId.toString() !== userId && !room) {
        return res.status(403).json({ message: 'Permission denied. You can only save your own files or shared files in the room.' });
      }

      savedFile = await File.findOneAndUpdate(
        { _id: fileId },
        { filename, language, code, updatedAt: Date.now() },
        { new: true }
      );
      isUpdate = true;
    } else {
      savedFile = await File.findOne({ userId, filename });
      if (savedFile) {
        savedFile = await File.findOneAndUpdate(
          { userId, filename },
          { language, code, updatedAt: Date.now() },
          { new: true }
        );
        isUpdate = true;
      } else {
        savedFile = new File({ userId, filename, language, code });
        await savedFile.save();
      }
    }

    const room = await Room.findOne({ users: { $elemMatch: { _id: userId } } });
    if (room) {
      io.to(room.roomId).emit('codeSaved', {
        roomId: room.roomId,
        fileId: savedFile._id,
        filename,
        language,
        code,
        userId: savedFile.userId,
        username: req.user.username || req.user.email.split('@')[0]
      });
    }

    res.json({
      fileId: savedFile._id,
      message: isUpdate ? 'File updated successfully' : 'File created successfully'
    });
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
    const file = await File.findOneAndDelete({ _id: fileId, userId });
    if (!file) {
      return res.status(404).json({ message: 'File not found or not authorized' });
    }
    res.json({ message: 'File deleted successfully' });
  } catch (error) {
    console.error('Error deleting file:', error);
    res.status(500).json({ message: 'Failed to delete file: ' + error.message });
  }
});

// Room Routes
const roomRoutes = express.Router();

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

    if (room.users.length === 0) {
      await Room.deleteOne({ roomId });
      console.log(`Room deleted (empty after kick): ${roomId}`);
    }

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
      }
    });
  } catch (error) {
    console.error('Failed to fetch Piston runtimes, using fallbacks:', error.message);
  }
}
fetchLanguageVersions();

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
app.use('/api/rooms', roomRoutes);

// Global Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err.stack);
  res.status(500).json({ message: err.message || 'Something went wrong!' });
});

// Start the Server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});