const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: { origin: 'http://localhost:3000', methods: ['GET', 'POST'] },
});

// Middleware
app.use(express.json());
app.use(cors({ origin: 'http://localhost:3000' }));

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/gameclash', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// JWT Secret (set in .env or here for development)
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key'; // Replace with a secure key or use .env

// Models
const userSchema = new mongoose.Schema({
  username: String,
  password: String, // Should be hashed in production
  role: String,
  elo: Number,
  games: [String],
  teams: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Team' }],
});

const tournamentSchema = new mongoose.Schema({
  name: String,
  game: String,
  status: String,
  start_date: Date,
  prize_pool: Number,
  current_funds: Number,
  is_team_based: Boolean,
  bracket_type: String,
  bracket: Object,
  active_teams: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Team' }],
  active_players: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  messages: [{ user: String, text: String, type: String, timestamp: Date }],
  schedule: [{ matchId: String, time: Date, location: String, reminderSent: Boolean }],
  stream_url: String,
});

const teamSchema = new mongoose.Schema({
  name: String,
  game: String,
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  captain: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  elo: Number,
  seed: Number,
  roles: [{ member: String, role: String }],
  tournaments: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Tournament' }],
});

const User = mongoose.model('User', userSchema);
const Tournament = mongoose.model('Tournament', tournamentSchema);
const Team = mongoose.model('Team', teamSchema);

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log('Token verification error:', err); // Debug token error
      if (err.name === 'TokenExpiredError') {
        return res.status(403).json({ error: 'Token expired. Please log in again.' });
      }
      return res.status(403).json({ error: 'Invalid token: ' + err.message });
    }
    console.log('Decoded token:', user); // Debug decoded token
    req.user = user;
    next();
  });
};

// Socket.IO Connection
io.on('connection', (socket) => {
  console.log('New client connected:', socket.id);

  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });

  // Handle real-time updates
  socket.on('tournamentUpdate', (data) => {
    io.emit('tournamentUpdate', data);
  });

  socket.on('teamUpdate', (data) => {
    io.emit('teamUpdate', data);
  });

  socket.on('bracketUpdate', (data) => {
    io.emit('bracketUpdate', data);
  });

  socket.on('messageUpdate', (data) => {
    io.emit('messageUpdate', data);
  });

  socket.on('scheduleUpdate', (data) => {
    io.emit('scheduleUpdate', data);
  });
});

// Routes
// Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  console.log('Login attempt:', { username, password }); // Debug login
  if (username === 'admin' && password === 'admin123') {
    const user = { id: '67c39f1290d480d94f66310f', role: 'organizer', username: 'admin' };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '7d' }); // 7-day expiration
    console.log('Generated token:', token); // Debug token
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// Get User Role
app.get('/user/role', authenticateToken, (req, res) => {
  res.json({ role: req.user.role, username: req.user.username });
});

// Get Tournaments
app.get('/tournaments', authenticateToken, async (req, res) => {
  try {
    const tournaments = await Tournament.find();
    res.json(tournaments);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch tournaments: ' + err.message });
  }
});

// Get Teams
app.get('/teams', authenticateToken, async (req, res) => {
  try {
    const teams = await Team.find();
    res.json(teams);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch teams: ' + err.message });
  }
});

// Public Tournaments (no auth required)
app.get('/public/tournaments/:id', async (req, res) => {
  try {
    const tournament = await Tournament.findById(req.params.id);
    if (!tournament) return res.status(404).json({ error: 'Tournament not found' });
    res.json(tournament);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch public tournament: ' + err.message });
  }
});

// Example Protected Route (Extend as needed)
app.post('/tournaments', authenticateToken, async (req, res) => {
  try {
    const tournament = new Tournament(req.body);
    await tournament.save();
    io.emit('tournamentUpdate', tournament);
    res.json(tournament);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create tournament: ' + err.message });
  }
});

app.post('/teams', authenticateToken, async (req, res) => {
  try {
    const team = new Team(req.body);
    await team.save();
    io.emit('teamUpdate', team);
    res.json(team);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create team: ' + err.message });
  }
});

// Server Start
const PORT = 3001;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  // Initialize test data (optional, remove in production)
  const initData = async () => {
    try {
      await User.findOneAndUpdate({ username: 'admin' }, { username: 'admin', role: 'organizer' }, { upsert: true });
      console.log('Admin user initialized');
    } catch (err) {
      console.error('Failed to initialize admin user:', err);
    }
  };
  initData();
});