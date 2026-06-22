const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const QRCode = require('qrcode');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./db');

const app = express();
const server = http.createServer(app);
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) { console.error('FATAL: JWT_SECRET env var is not set'); process.exit(1); }

const ALLOWED_ORIGINS = (process.env.FRONTEND_URL || 'http://localhost:3000')
  .split(',').map(s => s.trim());

const io = new Server(server, {
  cors: { origin: ALLOWED_ORIGINS, methods: ['GET', 'POST'] }
});

app.use(cors({ origin: ALLOWED_ORIGINS }));
app.use(express.json());

// ─── Migrations ───────────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);
try { db.exec(`ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'`); } catch {}
try { db.exec(`ALTER TABLE quizzes ADD COLUMN user_id TEXT`); } catch {}
db.exec(`
  CREATE TABLE IF NOT EXISTS game_results (
    id TEXT PRIMARY KEY,
    quiz_id TEXT NOT NULL,
    played_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    player_count INTEGER DEFAULT 0,
    avg_score REAL DEFAULT 0,
    question_tallies TEXT DEFAULT '[]'
  );
`);
db.exec(`
  CREATE TABLE IF NOT EXISTS active_games (
    code TEXT PRIMARY KEY,
    quiz_id TEXT NOT NULL,
    status TEXT DEFAULT 'lobby',
    current_question INTEGER DEFAULT -1,
    question_count INTEGER DEFAULT 0,
    players TEXT DEFAULT '[]',
    question_tallies TEXT DEFAULT '[]',
    join_url TEXT,
    last_reveal TEXT,
    last_ranking TEXT,
    team_mode INTEGER DEFAULT 0,
    teams TEXT DEFAULT '[]',
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);
try { db.exec(`ALTER TABLE active_games ADD COLUMN team_mode INTEGER DEFAULT 0`); } catch {}
try { db.exec(`ALTER TABLE active_games ADD COLUMN teams TEXT DEFAULT '[]'`); } catch {}

// ─── Middleware ───────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return res.status(401).json({ error: 'No autenticado' });
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

function requireAdmin(req, res, next) {
  const row = db.prepare('SELECT role FROM users WHERE id = ?').get(req.user.id);
  if (row?.role !== 'admin') return res.status(403).json({ error: 'Acceso denegado' });
  next();
}

// ─── Auth routes ──────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name?.trim() || !email?.trim() || !password) return res.status(400).json({ error: 'Todos los campos son requeridos' });
  if (password.length < 8) return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Email inválido' });

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase().trim());
  if (existing) return res.status(409).json({ error: 'Ya existe una cuenta con ese email' });

  const id = uuidv4();
  const hash = await bcrypt.hash(password, 12);
  db.prepare('INSERT INTO users (id, name, email, password_hash, role) VALUES (?, ?, ?, ?, ?)').run(
    id, name.trim(), email.toLowerCase().trim(), hash, 'user'
  );

  const user = { id, name: name.trim(), email: email.toLowerCase().trim(), role: 'user' };
  const token = jwt.sign(user, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email y contraseña requeridos' });

  const row = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase().trim());
  if (!row) return res.status(401).json({ error: 'Email o contraseña incorrectos' });

  const valid = await bcrypt.compare(password, row.password_hash);
  if (!valid) return res.status(401).json({ error: 'Email o contraseña incorrectos' });

  const user = { id: row.id, name: row.name, email: row.email, role: row.role || 'user' };
  const token = jwt.sign(user, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const row = db.prepare('SELECT id, name, email, role, created_at FROM users WHERE id = ?').get(req.user.id);
  if (!row) return res.status(404).json({ error: 'Usuario no encontrado' });
  res.json(row);
});

app.put('/api/auth/profile', requireAuth, async (req, res) => {
  const { name, currentPassword, newPassword } = req.body;
  const row = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!row) return res.status(404).json({ error: 'Usuario no encontrado' });

  if (newPassword) {
    if (!currentPassword) return res.status(400).json({ error: 'Ingresá tu contraseña actual' });
    const valid = await bcrypt.compare(currentPassword, row.password_hash);
    if (!valid) return res.status(401).json({ error: 'Contraseña actual incorrecta' });
    if (newPassword.length < 8) return res.status(400).json({ error: 'La nueva contraseña debe tener al menos 8 caracteres' });
    const hash = await bcrypt.hash(newPassword, 12);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, req.user.id);
  }

  const newName = name?.trim() || row.name;
  db.prepare('UPDATE users SET name = ? WHERE id = ?').run(newName, req.user.id);

  const user = { id: row.id, name: newName, email: row.email, role: row.role || 'user' };
  const token = jwt.sign(user, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user });
});

// ─── Admin: user management ───────────────────────────────────────────────────
app.get('/api/admin/users', requireAuth, requireAdmin, (req, res) => {
  const users = db.prepare(`
    SELECT u.id, u.name, u.email, u.role, u.created_at,
           COUNT(q.id) as quiz_count
    FROM users u
    LEFT JOIN quizzes q ON q.user_id = u.id
    GROUP BY u.id
    ORDER BY u.created_at ASC
  `).all();
  res.json(users);
});

app.put('/api/admin/users/:id/role', requireAuth, requireAdmin, (req, res) => {
  const { role } = req.body;
  if (!['user', 'admin'].includes(role)) return res.status(400).json({ error: 'Rol inválido' });
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'No podés cambiar tu propio rol' });
  db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, req.params.id);
  res.json({ ok: true });
});

app.delete('/api/admin/users/:id', requireAuth, requireAdmin, (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'No podés eliminar tu propia cuenta' });
  const quizzes = db.prepare('SELECT id FROM quizzes WHERE user_id = ?').all(req.params.id);
  quizzes.forEach(q => db.prepare('DELETE FROM questions WHERE quiz_id = ?').run(q.id));
  db.prepare('DELETE FROM quizzes WHERE user_id = ?').run(req.params.id);
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ─── Constants ────────────────────────────────────────────────────────────────
const TEAM_COLORS = ['#e74c3c','#3498db','#2ecc71','#f39c12','#9b59b6','#1abc9c'];

// ─── In-memory game state ─────────────────────────────────────────────────────
const games = {};

function createGameState(quizId) {
  return {
    quizId,
    status: 'lobby',
    currentQuestion: -1,
    questionCount: 0,
    players: {},
    questionTimer: null,
    countdownTimer: null,
    timeLeft: 0,
    lastReveal: null,
    lastRanking: null,
    questionTallies: [],
    currentQ: null,
    teamMode: false,
    teams: [],
  };
}

function getTeamCounts(game) {
  const counts = {};
  game.teams.forEach(t => { counts[t.id] = 0; });
  Object.values(game.players).forEach(p => {
    if (p.teamId && counts[p.teamId] !== undefined) counts[p.teamId]++;
  });
  return game.teams.map(t => ({ ...t, count: counts[t.id] || 0 }));
}

function getTeamRanking(game) {
  const totals = {};
  game.teams.forEach(t => { totals[t.id] = { id: t.id, name: t.name, color: t.color, score: 0, playerCount: 0 }; });
  Object.values(game.players).forEach(p => {
    if (p.teamId && totals[p.teamId]) {
      totals[p.teamId].score += p.score;
      totals[p.teamId].playerCount++;
    }
  });
  return Object.values(totals)
    .sort((a, b) => b.score - a.score)
    .map((t, i) => ({ ...t, rank: i + 1 }));
}

function persistGame(code) {
  const game = games[code];
  if (!game) return;
  const players = Object.values(game.players).map(p => ({
    name: p.name, emoji: p.emoji, score: p.score, streak: p.streak || 0, teamId: p.teamId || null
  }));
  db.prepare(`INSERT OR REPLACE INTO active_games
    (code, quiz_id, status, current_question, question_count, players, question_tallies, join_url, last_reveal, last_ranking, team_mode, teams, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
  `).run(
    code, game.quizId, game.status, game.currentQuestion, game.questionCount || 0,
    JSON.stringify(players), JSON.stringify(game.questionTallies), game.joinUrl || null,
    game.lastReveal ? JSON.stringify(game.lastReveal) : null,
    game.lastRanking ? JSON.stringify(game.lastRanking) : null,
    game.teamMode ? 1 : 0, JSON.stringify(game.teams || [])
  );
}

function loadActiveGames() {
  try {
    const rows = db.prepare(
      `SELECT * FROM active_games WHERE updated_at > datetime('now', '-12 hours')`
    ).all();
    rows.forEach(row => {
      const players = JSON.parse(row.players || '[]');
      const playersMap = {};
      players.forEach((p, i) => {
        playersMap[`restored_${i}`] = { ...p, answered: false, lastAnswer: null };
      });
      const status = row.status === 'question' || row.status === 'countdown' ? 'results' : row.status;
      games[row.code] = {
        quizId: row.quiz_id, status,
        currentQuestion: row.current_question,
        questionCount: row.question_count || 0,
        players: playersMap,
        questionTimer: null, countdownTimer: null,
        timeLeft: 0,
        lastReveal: row.last_reveal ? JSON.parse(row.last_reveal) : null,
        lastRanking: row.last_ranking ? JSON.parse(row.last_ranking) : null,
        questionTallies: JSON.parse(row.question_tallies || '[]'),
        joinUrl: row.join_url, currentQ: null,
        teamMode: !!row.team_mode,
        teams: JSON.parse(row.teams || '[]'),
      };
    });
    if (rows.length) console.log(`Restored ${rows.length} active game(s) from DB`);
  } catch (e) { console.warn('loadActiveGames error:', e.message); }
}

loadActiveGames();

// ─── REST API ─────────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({ ok: true }));

app.get('/api/quizzes', requireAuth, (req, res) => {
  const quizzes = db.prepare(`
    SELECT q.*, COUNT(qs.id) as question_count
    FROM quizzes q
    LEFT JOIN questions qs ON q.id = qs.quiz_id
    WHERE q.user_id = ?
    GROUP BY q.id
    ORDER BY q.created_at DESC
  `).all(req.user.id);
  res.json(quizzes);
});

app.get('/api/quizzes/:id', requireAuth, (req, res) => {
  const quiz = db.prepare('SELECT * FROM quizzes WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!quiz) return res.status(404).json({ error: 'Quiz no encontrado' });
  const questions = db.prepare('SELECT * FROM questions WHERE quiz_id = ? ORDER BY position').all(quiz.id);
  questions.forEach(q => { q.options = JSON.parse(q.options); });
  res.json({ ...quiz, questions });
});

function validateQuestions(questions) {
  if (!Array.isArray(questions) || questions.length === 0) return 'Se requiere al menos una pregunta';
  for (const q of questions) {
    if (!q.text?.trim()) return 'Cada pregunta debe tener texto';
    if (!Array.isArray(q.options) || q.options.length < 2 || q.options.length > 4) return 'Cada pregunta debe tener 2–4 opciones';
    if (!q.options.every(o => typeof o === 'string' && o.trim())) return 'Todas las opciones deben ser texto no vacío';
    const ci = parseInt(q.correctIndex, 10);
    if (!Number.isInteger(ci) || ci < 0 || ci >= q.options.length) return 'correctIndex fuera de rango';
  }
  return null;
}

app.post('/api/quizzes', requireAuth, (req, res) => {
  const { title, questions } = req.body;
  if (!title) return res.status(400).json({ error: 'Título requerido' });
  const err = validateQuestions(questions);
  if (err) return res.status(400).json({ error: err });

  const id = uuidv4();
  db.prepare('INSERT INTO quizzes (id, title, user_id) VALUES (?, ?, ?)').run(id, title, req.user.id);

  const insertQ = db.prepare(`
    INSERT INTO questions (id, quiz_id, text, options, correct_index, time_limit, position)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  questions.forEach((q, i) => {
    insertQ.run(uuidv4(), id, q.text.trim(), JSON.stringify(q.options.map(o => o.trim())), parseInt(q.correctIndex, 10), q.timeLimit || 20, i);
  });

  res.json({ id });
});

app.put('/api/quizzes/:id', requireAuth, (req, res) => {
  const { title, questions } = req.body;
  if (!title) return res.status(400).json({ error: 'Título requerido' });
  const err = validateQuestions(questions);
  if (err) return res.status(400).json({ error: err });

  const quiz = db.prepare('SELECT * FROM quizzes WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!quiz) return res.status(404).json({ error: 'Quiz no encontrado' });

  db.prepare('UPDATE quizzes SET title = ? WHERE id = ?').run(title, req.params.id);
  db.prepare('DELETE FROM questions WHERE quiz_id = ?').run(req.params.id);

  const insertQ = db.prepare(`
    INSERT INTO questions (id, quiz_id, text, options, correct_index, time_limit, position)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  questions.forEach((q, i) => {
    insertQ.run(uuidv4(), req.params.id, q.text.trim(), JSON.stringify(q.options.map(o => o.trim())), parseInt(q.correctIndex, 10), q.timeLimit || 20, i);
  });

  res.json({ ok: true });
});

app.delete('/api/quizzes/:id', requireAuth, (req, res) => {
  const quiz = db.prepare('SELECT * FROM quizzes WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!quiz) return res.status(404).json({ error: 'Quiz no encontrado' });
  db.prepare('DELETE FROM game_results WHERE quiz_id = ?').run(req.params.id);
  db.prepare('DELETE FROM questions WHERE quiz_id = ?').run(req.params.id);
  db.prepare('DELETE FROM quizzes WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.get('/api/quizzes/:id/stats', requireAuth, (req, res) => {
  const quiz = db.prepare('SELECT * FROM quizzes WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!quiz) return res.status(404).json({ error: 'Quiz no encontrado' });

  const results = db.prepare('SELECT * FROM game_results WHERE quiz_id = ? ORDER BY played_at DESC').all(req.params.id);
  const questions = db.prepare('SELECT * FROM questions WHERE quiz_id = ? ORDER BY position').all(req.params.id);

  if (!results.length) return res.json({ playCount: 0, avgScore: 0, avgPlayers: 0, mostMissedQuestion: null, recentGames: [] });

  const playCount = results.length;
  const avgScore = Math.round(results.reduce((s, r) => s + r.avg_score, 0) / playCount);
  const avgPlayers = Math.round(results.reduce((s, r) => s + r.player_count, 0) / playCount);

  // Aggregate tallies per question index across all games
  const aggregated = questions.map(() => [0, 0, 0, 0]);
  results.forEach(r => {
    try {
      const tallies = JSON.parse(r.question_tallies);
      tallies.forEach((t, qi) => {
        if (!aggregated[qi] || !Array.isArray(t)) return;
        t.forEach((v, oi) => { aggregated[qi][oi] = (aggregated[qi][oi] || 0) + v; });
      });
    } catch {}
  });

  // Find most-missed question (highest wrong answer rate)
  let mostMissedQuestion = null;
  let worstPct = -1;
  questions.forEach((q, i) => {
    const tally = aggregated[i];
    const total = tally.reduce((s, v) => s + v, 0);
    if (!total) return;
    const wrongPct = Math.round((1 - (tally[q.correct_index] || 0) / total) * 100);
    if (wrongPct > worstPct) {
      worstPct = wrongPct;
      mostMissedQuestion = { text: q.text, wrongPct, position: i + 1 };
    }
  });

  const recentGames = results.slice(0, 5).map(r => ({
    playedAt: r.played_at,
    playerCount: r.player_count,
    avgScore: Math.round(r.avg_score)
  }));

  res.json({ playCount, avgScore, avgPlayers, mostMissedQuestion, recentGames });
});

app.post('/api/games', requireAuth, async (req, res) => {
  const { quizId, baseUrl, teamMode, teams } = req.body;
  const quiz = db.prepare('SELECT * FROM quizzes WHERE id = ? AND user_id = ?').get(quizId, req.user.id);
  if (!quiz) return res.status(404).json({ error: 'Quiz no encontrado' });

  let code;
  do { code = Math.random().toString(36).substring(2, 8).toUpperCase(); } while (games[code]);
  const joinUrl = `${baseUrl || process.env.FRONTEND_URL || 'http://localhost:3000'}/player?code=${code}`;

  const qrDataUrl = await QRCode.toDataURL(joinUrl, {
    width: 300, margin: 2,
    color: { dark: '#1a1a2e', light: '#ffffff' }
  });

  games[code] = createGameState(quizId);
  games[code].joinUrl = joinUrl;
  games[code].qr = qrDataUrl;

  if (teamMode && Array.isArray(teams) && teams.length >= 2) {
    games[code].teamMode = true;
    games[code].teams = teams.slice(0, 6).map((name, i) => ({
      id: `team_${i}`,
      name: String(name).trim().substring(0, 20) || `Equipo ${i + 1}`,
      color: TEAM_COLORS[i]
    }));
  }

  res.json({ code, joinUrl, qr: qrDataUrl, teamMode: games[code].teamMode, teams: games[code].teams });
});

app.get('/api/games/:code', (req, res) => {
  const game = games[req.params.code];
  if (!game) return res.status(404).json({ error: 'Sala no encontrada' });
  res.json({ status: game.status, playerCount: Object.keys(game.players).length, joinUrl: game.joinUrl });
});

// ─── WebSocket ────────────────────────────────────────────────────────────────
io.on('connection', (socket) => {

  socket.on('admin:join', ({ code, token }) => {
    // Verify JWT and quiz ownership
    if (!token) return socket.emit('error', 'No autorizado');
    let user;
    try { user = jwt.verify(token, JWT_SECRET); } catch { return socket.emit('error', 'No autorizado'); }

    const game = games[code];
    if (!game) return socket.emit('error', 'Sala no encontrada');

    const quiz = db.prepare('SELECT user_id FROM quizzes WHERE id = ?').get(game.quizId);
    const dbUser = db.prepare('SELECT role FROM users WHERE id = ?').get(user.id);
    if (quiz?.user_id !== user.id && dbUser?.role !== 'admin') {
      return socket.emit('error', 'No autorizado');
    }

    socket.join(`game:${code}`);
    socket.gameCode = code;
    socket.role = 'admin';
    socket.emit('admin:state', {
      status: game.status,
      players: Object.values(game.players).map(p => ({ name: p.name, score: p.score })),
      currentQuestion: game.currentQuestion
    });
  });

  socket.on('player:join', ({ code, name, emoji }) => {
    const game = games[code];
    if (!game) return socket.emit('error', 'Sala no encontrada');
    if (!name?.trim()) return socket.emit('error', 'Nombre requerido');

    const playerName = name.trim().substring(0, 20);
    const playerEmoji = (emoji && typeof emoji === 'string') ? emoji.trim().substring(0, 4) : '😎';

    // Allow reconnect during an active game if the player name matches
    if (game.status !== 'lobby') {
      const existing = Object.entries(game.players).find(([, p]) => p.name === playerName);
      if (!existing) return socket.emit('error', 'El juego ya comenzó');

      const [oldId, playerData] = existing;
      delete game.players[oldId];
      playerData.disconnected = false;
      game.players[socket.id] = playerData;
      socket.join(`game:${code}`);
      socket.gameCode = code;
      socket.role = 'player';
      socket.emit('player:joined', { name: playerName });

      // Restore current game state
      if (game.status === 'question' && game.currentQ) {
        socket.emit('question:start', {
          index: game.currentQuestion,
          total: game.questionCount || 1,
          text: game.currentQ.text,
          options: game.currentQ.options,
          timeLimit: game.currentQ.time_limit
        });
        socket.emit('timer:tick', { timeLeft: game.timeLeft });
      } else if (game.status === 'results' && game.lastReveal) {
        socket.emit('question:reveal', {
          correctIndex: game.lastReveal.correctIndex,
          tally: game.lastReveal.tally,
          ranking: game.lastReveal.ranking
        });
      } else if (game.status === 'finished' && game.lastRanking) {
        socket.emit('game:finished', { ranking: game.lastRanking });
      }
      return;
    }

    const nameExists = Object.values(game.players).some(p => p.name === playerName);
    if (nameExists) return socket.emit('error', 'Ese nombre ya está en uso, elegí otro');

    game.players[socket.id] = { name: playerName, emoji: playerEmoji, score: 0, answered: false, streak: 0 };
    socket.join(`game:${code}`);
    socket.gameCode = code;
    socket.role = 'player';

    socket.emit('player:joined', { name: playerName, teamMode: game.teamMode, teams: game.teams });
    io.to(`game:${code}`).emit('lobby:update', {
      players: Object.values(game.players).map(p => ({ name: p.name, emoji: p.emoji, score: p.score, teamId: p.teamId || null })),
      teamMode: game.teamMode,
      teams: game.teamMode ? getTeamCounts(game) : []
    });
    persistGame(code);
  });

  socket.on('player:team', ({ teamId }) => {
    const code = socket.gameCode;
    const game = games[code];
    if (!game || socket.role !== 'player' || game.status !== 'lobby') return;
    const player = game.players[socket.id];
    if (!player || !game.teams.find(t => t.id === teamId)) return;
    player.teamId = teamId;
    io.to(`game:${code}`).emit('team:update', { teams: getTeamCounts(game) });
  });

  socket.on('player:react', ({ emoji }) => {
    const code = socket.gameCode;
    const game = games[code];
    if (!game || socket.role !== 'player') return;
    const player = game.players[socket.id];
    if (!player) return;
    io.to(`game:${code}`).emit('reaction:new', { emoji, playerName: player.name });
  });

  socket.on('screen:join', ({ code }) => {
    const game = games[code];
    if (!game) return socket.emit('error', 'Sala no encontrada');
    socket.join(`game:${code}`);
    socket.gameCode = code;
    socket.role = 'screen';

    const payload = {
      status: game.status,
      players: Object.values(game.players).map(p => ({ name: p.name, emoji: p.emoji, score: p.score, teamId: p.teamId || null })),
      joinUrl: game.joinUrl,
      qr: game.qr || null,
      teamMode: game.teamMode,
      teams: game.teamMode ? getTeamCounts(game) : []
    };

    if (game.status === 'question' && game.currentQuestion >= 0) {
      const questions = db.prepare('SELECT * FROM questions WHERE quiz_id = ? ORDER BY position').all(game.quizId);
      const q = questions[game.currentQuestion];
      if (q) {
        payload.currentQuestion = {
          index: game.currentQuestion,
          total: questions.length,
          text: q.text,
          options: JSON.parse(q.options),
          timeLimit: q.time_limit,
          timeLeft: game.timeLeft
        };
      }
    } else if (game.status === 'results' && game.lastReveal) {
      payload.currentReveal = game.lastReveal;
    } else if (game.status === 'finished' && game.lastRanking) {
      payload.finalRanking = game.lastRanking;
    }

    socket.emit('screen:state', payload);
  });

  socket.on('admin:next', ({ token } = {}) => {
    const code = socket.gameCode;
    const game = games[code];
    if (!game) return;
    if (socket.role !== 'admin') {
      if (!token) return;
      try {
        const u = jwt.verify(token, JWT_SECRET);
        const quiz = db.prepare('SELECT user_id FROM quizzes WHERE id = ?').get(game.quizId);
        const dbUser = db.prepare('SELECT role FROM users WHERE id = ?').get(u.id);
        if (quiz?.user_id !== u.id && dbUser?.role !== 'admin') return;
      } catch { return; }
    }
    if (game.status === 'countdown' || game.status === 'question') return;

    const questions = db.prepare('SELECT * FROM questions WHERE quiz_id = ? ORDER BY position').all(game.quizId);
    game.currentQuestion++;

    if (game.currentQuestion >= questions.length) {
      game.status = 'finished';
      clearInterval(game.questionTimer);
      clearTimeout(game.countdownTimer);
      const ranking = game.teamMode
        ? getTeamRanking(game)
        : Object.values(game.players)
            .sort((a, b) => b.score - a.score)
            .map((p, i) => ({ rank: i + 1, name: p.name, emoji: p.emoji, score: p.score }));
      game.lastRanking = ranking;
      io.to(`game:${code}`).emit('game:finished', { ranking, teamMode: game.teamMode });

      try {
        const scores = Object.values(game.players).map(p => p.score);
        const avgScore = scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;
        db.prepare('INSERT INTO game_results (id, quiz_id, player_count, avg_score, question_tallies) VALUES (?, ?, ?, ?, ?)')
          .run(uuidv4(), game.quizId, scores.length, avgScore, JSON.stringify(game.questionTallies));
      } catch (e) { console.warn('Stats save error:', e.message); }

      persistGame(code);
      db.prepare(`DELETE FROM active_games WHERE code = ?`).run(code);
      return;
    }

    const q = questions[game.currentQuestion];
    q.options = JSON.parse(q.options);
    game.currentQ = q;
    game.questionCount = questions.length;
    game.status = 'countdown';

    clearInterval(game.questionTimer);
    Object.values(game.players).forEach(p => { p.answered = false; p.lastAnswer = null; });

    // Broadcast countdown to all clients
    io.to(`game:${code}`).emit('question:countdown', {
      seconds: 3,
      index: game.currentQuestion,
      total: questions.length
    });

    // Start question after countdown
    game.countdownTimer = setTimeout(() => {
      game.status = 'question';
      game.timeLeft = q.time_limit;

      io.to(`game:${code}`).emit('question:start', {
        index: game.currentQuestion,
        total: questions.length,
        text: q.text,
        options: q.options,
        timeLimit: q.time_limit
      });

      game.questionTimer = setInterval(() => {
        game.timeLeft--;
        io.to(`game:${code}`).emit('timer:tick', { timeLeft: game.timeLeft });
        if (game.timeLeft <= 0) {
          clearInterval(game.questionTimer);
          revealAnswers(code, q);
        }
      }, 1000);

      persistGame(code);
    }, 3000);
  });

  socket.on('player:answer', ({ answerIndex }) => {
    const code = socket.gameCode;
    const game = games[code];
    if (!game || game.status !== 'question') return;
    const player = game.players[socket.id];
    if (!player || player.answered) return;

    const q = game.currentQ;
    if (!q) return;

    const idx = parseInt(answerIndex, 10);
    const options = typeof q.options === 'string' ? JSON.parse(q.options) : q.options;
    if (!Number.isInteger(idx) || idx < 0 || idx >= options.length) return;

    player.answered = true;
    player.lastAnswer = idx;

    const correct = idx === q.correct_index;
    if (correct) {
      const bonus = Math.round((game.timeLeft / q.time_limit) * 500);
      player.score += 500 + bonus;
      player.streak = (player.streak || 0) + 1;
    } else {
      player.streak = 0;
    }

    let rank, totalEntities;
    if (game.teamMode) {
      const teamRanking = getTeamRanking(game);
      const myTeam = teamRanking.find(t => t.id === player.teamId);
      rank = myTeam?.rank || 1;
      totalEntities = game.teams.length;
    } else {
      const sortedScores = Object.values(game.players).map(p => p.score).sort((a, b) => b - a);
      rank = sortedScores.indexOf(player.score) + 1;
      totalEntities = Object.keys(game.players).length;
    }

    // Team score for display on player wait screen
    let teamScore = null;
    if (game.teamMode && player.teamId) {
      teamScore = Object.values(game.players)
        .filter(p => p.teamId === player.teamId)
        .reduce((s, p) => s + p.score, 0);
    }

    socket.emit('player:answer:result', {
      score: player.score, streak: player.streak,
      rank, totalPlayers: totalEntities,
      teamMode: game.teamMode, teamScore
    });

    // Broadcast live progress to all players in the room
    const answeredCount = Object.values(game.players).filter(p => p.answered).length;
    const totalCount = Object.keys(game.players).length;
    const liveRanking = game.teamMode
      ? getTeamRanking(game).slice(0, 6)
      : Object.values(game.players)
          .sort((a, b) => b.score - a.score)
          .slice(0, 6)
          .map(p => ({ name: p.name, emoji: p.emoji, score: p.score }));
    io.to(`game:${code}`).emit('answer:progress', {
      answered: answeredCount, total: totalCount,
      ranking: liveRanking, teamMode: game.teamMode
    });

    const connected = Object.values(game.players).filter(p => !p.disconnected);
    const allAnswered = connected.length > 0 && connected.every(p => p.answered);
    if (allAnswered) {
      clearInterval(game.questionTimer);
      revealAnswers(code, q);
    }
  });

  socket.on('admin:reveal', ({ token } = {}) => {
    const code = socket.gameCode;
    const game = games[code];
    if (!game) return;
    if (socket.role !== 'admin') {
      if (!token) return;
      try {
        const u = jwt.verify(token, JWT_SECRET);
        const quiz = db.prepare('SELECT user_id FROM quizzes WHERE id = ?').get(game.quizId);
        const dbUser = db.prepare('SELECT role FROM users WHERE id = ?').get(u.id);
        if (quiz?.user_id !== u.id && dbUser?.role !== 'admin') return;
      } catch { return; }
    }
    clearInterval(game.questionTimer);
    const questions = db.prepare('SELECT * FROM questions WHERE quiz_id = ? ORDER BY position').all(game.quizId);
    const q = questions[game.currentQuestion];
    if (!q) return;
    revealAnswers(code, q);
  });

  socket.on('disconnect', () => {
    const code = socket.gameCode;
    if (!code || !games[code]) return;
    const game = games[code];
    if (socket.role === 'player') {
      const player = game.players[socket.id];
      if (!player) return;
      if (game.status === 'lobby') {
        delete game.players[socket.id];
        persistGame(code);
      } else {
        // Keep player in game for ranking; mark disconnected so they don't block allAnswered
        player.disconnected = true;
        // If everyone still connected has answered, reveal early
        const connected = Object.values(game.players).filter(p => !p.disconnected);
        if (game.status === 'question' && connected.length > 0 && connected.every(p => p.answered)) {
          clearInterval(game.questionTimer);
          revealAnswers(code, game.currentQ);
        }
      }
      io.to(`game:${code}`).emit('lobby:update', {
        players: Object.values(game.players)
          .filter(p => !p.disconnected)
          .map(p => ({ name: p.name, emoji: p.emoji, score: p.score, teamId: p.teamId || null })),
        teamMode: game.teamMode,
        teams: game.teamMode ? getTeamCounts(game) : []
      });
    }
  });
});

function revealAnswers(code, q) {
  const game = games[code];
  if (!game || game.status !== 'question') return;
  game.status = 'results';

  const options = typeof q.options === 'string' ? JSON.parse(q.options) : q.options;
  Object.values(game.players).forEach(p => { if (!p.answered) p.streak = 0; });
  const tally = options.map((_, i) =>
    Object.values(game.players).filter(p => p.lastAnswer === i).length
  );

  const ranking = game.teamMode
    ? getTeamRanking(game).slice(0, 5)
    : Object.values(game.players)
        .sort((a, b) => b.score - a.score)
        .slice(0, 5)
        .map((p, i) => ({ rank: i + 1, name: p.name, emoji: p.emoji, score: p.score }));

  game.lastReveal = { correctIndex: q.correct_index, tally, ranking, questionText: q.text, options, teamMode: game.teamMode };
  game.questionTallies[game.currentQuestion] = tally;

  io.to(`game:${code}`).emit('question:reveal', { correctIndex: q.correct_index, tally, ranking, teamMode: game.teamMode });
  persistGame(code);
}

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 4000;
server.listen(PORT, () => console.log(`Synapto backend running on port ${PORT}`));
