const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const passport = require('passport');
const GitHubStrategy = require('passport-github2').Strategy;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
require('dotenv').config();

const app = express();

app.use(cors({
  origin: 'http://localhost:4200',
  credentials: true
}));
app.use(express.json());
app.use(passport.initialize());

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
  if (!this.isModified('password') || !this.password) {
    return next();
  }
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

const User = mongoose.model('User', UserSchema);

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
          password: Math.random().toString(36).slice(-8)
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

const authRoutes = express.Router();

authRoutes.post('/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ message: 'User already exists' });
    }
    user = new User({ email, password, provider: 'local', username: email.split('@')[0] });
    await user.save();
    const token = jwt.sign({ email: user.email, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ message: 'Signup failed: ' + error.message });
  }
});

authRoutes.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email }).select('+password');
    if (!user || !user.password) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign({ email: user.email, username: user.username || email.split('@')[0] }, process.env.JWT_SECRET, { expiresIn: '1h' });
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
        console.error('GitHub authentication failed: No user found');
        return res.redirect('http://localhost:4200/auth/callback?error=GitHub authentication failed: No user found');
      }
      const token = jwt.sign(
        { email: req.user.email, username: req.user.username },
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

const PISTON_API_URL = 'https://emkc.org/api/v2/piston/execute';

let cppVersion = '10.2.0'; 
async function fetchCppVersion() {
  try {
    const response = await axios.get('https://emkc.org/api/v2/piston/runtimes');
    const cppRuntimes = response.data.filter(r => r.language === 'cpp');
    if (cppRuntimes.length > 0) {
      cppVersion = cppRuntimes[0].version; 
      console.log(`Fetched C++ version: ${cppVersion}`);
    } else {
      console.log('No C++ runtimes found, using fallback:', cppVersion);
    }
  } catch (error) {
    console.error('Failed to fetch Piston runtimes, using fallback:', error.message);
  }
}
fetchCppVersion(); 

app.post('/api/run', auth, async (req, res) => {
  const { code, language, input } = req.body;

  if (!code || !language) {
    return res.status(400).json({ error: 'Code and language are required' });
  }

  if (language !== 'cpp') {
    return res.status(400).json({ error: 'Only C++ is supported currently' });
  }

  try {
    console.log('Sending to Piston API:', { code, language, input, version: cppVersion });

    const pistonResponse = await axios.post(PISTON_API_URL, {
      language: 'cpp',
      version: cppVersion, // Use dynamically fetched version
      files: [{
        name: 'main.cpp',
        content: code
      }],
      stdin: input || '', // Pass user input to stdin
      args: [],
      compile_timeout: 10000, // 10 seconds
      run_timeout: 3000 // 3 seconds
    }, {
      headers: { 'Content-Type': 'application/json' }
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