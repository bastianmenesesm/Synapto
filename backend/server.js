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
const JWT_SECRET = process.env.JWT_SECRET || 'synapto_dev_secret_change_in_prod';

const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

app.use(cors());
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

// ─── In-memory game state ─────────────────────────────────────────────────────
const games = {};

function createGameState(quizId) {
  return {
    quizId,
    status: 'lobby',
    currentQuestion: -1,
    players: {},
    questionTimer: null,
    timeLeft: 0,
    lastReveal: null,
    lastRanking: null,
    questionTallies: [],
  };
}

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

app.post('/api/quizzes', requireAuth, (req, res) => {
  const { title, questions } = req.body;
  if (!title || !questions?.length) return res.status(400).json({ error: 'Título y preguntas requeridos' });

  const id = uuidv4();
  db.prepare('INSERT INTO quizzes (id, title, user_id) VALUES (?, ?, ?)').run(id, title, req.user.id);

  const insertQ = db.prepare(`
    INSERT INTO questions (id, quiz_id, text, options, correct_index, time_limit, position)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  questions.forEach((q, i) => {
    insertQ.run(uuidv4(), id, q.text, JSON.stringify(q.options), q.correctIndex, q.timeLimit || 20, i);
  });

  res.json({ id });
});

app.put('/api/quizzes/:id', requireAuth, (req, res) => {
  const { title, questions } = req.body;
  const quiz = db.prepare('SELECT * FROM quizzes WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!quiz) return res.status(404).json({ error: 'Quiz no encontrado' });

  db.prepare('UPDATE quizzes SET title = ? WHERE id = ?').run(title, req.params.id);
  db.prepare('DELETE FROM questions WHERE quiz_id = ?').run(req.params.id);

  const insertQ = db.prepare(`
    INSERT INTO questions (id, quiz_id, text, options, correct_index, time_limit, position)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  questions.forEach((q, i) => {
    insertQ.run(uuidv4(), req.params.id, q.text, JSON.stringify(q.options), q.correctIndex, q.timeLimit || 20, i);
  });

  res.json({ ok: true });
});

app.delete('/api/quizzes/:id', requireAuth, (req, res) => {
  const quiz = db.prepare('SELECT * FROM quizzes WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!quiz) return res.status(404).json({ error: 'Quiz no encontrado' });
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
  const { quizId, baseUrl } = req.body;
  const quiz = db.prepare('SELECT * FROM quizzes WHERE id = ? AND user_id = ?').get(quizId, req.user.id);
  if (!quiz) return res.status(404).json({ error: 'Quiz no encontrado' });

  const code = Math.random().toString(36).substring(2, 8).toUpperCase();
  const joinUrl = `${baseUrl || process.env.FRONTEND_URL || 'http://localhost:3000'}/player?code=${code}`;

  const qrDataUrl = await QRCode.toDataURL(joinUrl, {
    width: 300, margin: 2,
    color: { dark: '#1a1a2e', light: '#ffffff' }
  });

  games[code] = createGameState(quizId);
  games[code].joinUrl = joinUrl;

  res.json({ code, joinUrl, qr: qrDataUrl });
});

app.get('/api/games/:code', (req, res) => {
  const game = games[req.params.code];
  if (!game) return res.status(404).json({ error: 'Sala no encontrada' });
  res.json({ status: game.status, playerCount: Object.keys(game.players).length, joinUrl: game.joinUrl });
});

// ─── WebSocket ────────────────────────────────────────────────────────────────
io.on('connection', (socket) => {

  socket.on('admin:join', ({ code }) => {
    const game = games[code];
    if (!game) return socket.emit('error', 'Sala no encontrada');
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
    if (game.status !== 'lobby') return socket.emit('error', 'El juego ya comenzó');
    if (!name?.trim()) return socket.emit('error', 'Nombre requerido');

    const playerName = name.trim().substring(0, 20);
    const playerEmoji = (emoji && typeof emoji === 'string') ? emoji.trim().substring(0, 4) : '😎';
    game.players[socket.id] = { name: playerName, emoji: playerEmoji, score: 0, answered: false, streak: 0 };
    socket.join(`game:${code}`);
    socket.gameCode = code;
    socket.role = 'player';

    socket.emit('player:joined', { name: playerName });
    io.to(`game:${code}`).emit('lobby:update', {
      players: Object.values(game.players).map(p => ({ name: p.name, emoji: p.emoji, score: p.score }))
    });
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
      players: Object.values(game.players).map(p => ({ name: p.name, emoji: p.emoji, score: p.score })),
      joinUrl: game.joinUrl
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

  socket.on('admin:next', () => {
    const code = socket.gameCode;
    const game = games[code];
    if (!game || socket.role !== 'admin') return;

    const questions = db.prepare('SELECT * FROM questions WHERE quiz_id = ? ORDER BY position').all(game.quizId);
    game.currentQuestion++;

    if (game.currentQuestion >= questions.length) {
      game.status = 'finished';
      clearInterval(game.questionTimer);
      const ranking = Object.values(game.players)
        .sort((a, b) => b.score - a.score)
        .map((p, i) => ({ rank: i + 1, name: p.name, emoji: p.emoji, score: p.score }));
      game.lastRanking = ranking;
      io.to(`game:${code}`).emit('game:finished', { ranking });

      // Persist game stats
      try {
        const scores = Object.values(game.players).map(p => p.score);
        const avgScore = scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;
        db.prepare('INSERT INTO game_results (id, quiz_id, player_count, avg_score, question_tallies) VALUES (?, ?, ?, ?, ?)')
          .run(uuidv4(), game.quizId, scores.length, avgScore, JSON.stringify(game.questionTallies));
      } catch (e) { console.warn('Stats save error:', e.message); }
      return;
    }

    const q = questions[game.currentQuestion];
    q.options = JSON.parse(q.options);
    game.status = 'question';
    game.timeLeft = q.time_limit;

    Object.values(game.players).forEach(p => { p.answered = false; p.lastAnswer = null; p._prevStreak = p.streak; });

    const questionPayload = {
      index: game.currentQuestion,
      total: questions.length,
      text: q.text,
      options: q.options,
      timeLimit: q.time_limit
    };

    io.to(`game:${code}`).emit('question:start', questionPayload);

    clearInterval(game.questionTimer);
    game.questionTimer = setInterval(() => {
      game.timeLeft--;
      io.to(`game:${code}`).emit('timer:tick', { timeLeft: game.timeLeft });
      if (game.timeLeft <= 0) {
        clearInterval(game.questionTimer);
        revealAnswers(code, q);
      }
    }, 1000);
  });

  socket.on('player:answer', ({ answerIndex }) => {
    const code = socket.gameCode;
    const game = games[code];
    if (!game || game.status !== 'question') return;
    const player = game.players[socket.id];
    if (!player || player.answered) return;

    const questions = db.prepare('SELECT * FROM questions WHERE quiz_id = ? ORDER BY position').all(game.quizId);
    const q = questions[game.currentQuestion];

    player.answered = true;
    player.lastAnswer = answerIndex;

    const correct = answerIndex === q.correct_index;
    if (correct) {
      const bonus = Math.round((game.timeLeft / q.time_limit) * 500);
      player.score += 500 + bonus;
      player.streak = (player.streak || 0) + 1;
    } else {
      player.streak = 0;
    }

    socket.emit('player:answer:result', { correct, correctIndex: q.correct_index, score: player.score, streak: player.streak });

    const allAnswered = Object.values(game.players).every(p => p.answered);
    if (allAnswered) {
      clearInterval(game.questionTimer);
      revealAnswers(code, q);
    }
  });

  socket.on('admin:reveal', () => {
    const code = socket.gameCode;
    const game = games[code];
    if (!game || socket.role !== 'admin') return;
    clearInterval(game.questionTimer);
    const questions = db.prepare('SELECT * FROM questions WHERE quiz_id = ? ORDER BY position').all(game.quizId);
    revealAnswers(code, questions[game.currentQuestion]);
  });

  socket.on('disconnect', () => {
    const code = socket.gameCode;
    if (!code || !games[code]) return;
    const game = games[code];
    if (socket.role === 'player') {
      delete game.players[socket.id];
      io.to(`game:${code}`).emit('lobby:update', {
        players: Object.values(game.players).map(p => ({ name: p.name, emoji: p.emoji, score: p.score }))
      });
    }
  });
});

function revealAnswers(code, q) {
  const game = games[code];
  if (!game) return;
  game.status = 'results';

  const options = typeof q.options === 'string' ? JSON.parse(q.options) : q.options;
  // Reset streak for players who didn't answer
  Object.values(game.players).forEach(p => { if (!p.answered) p.streak = 0; });
  const tally = options.map((_, i) =>
    Object.values(game.players).filter(p => p.lastAnswer === i).length
  );

  const ranking = Object.values(game.players)
    .sort((a, b) => b.score - a.score)
    .slice(0, 5)
    .map((p, i) => ({ rank: i + 1, name: p.name, emoji: p.emoji, score: p.score }));

  game.lastReveal = { correctIndex: q.correct_index, tally, ranking, questionText: q.text, options };
  game.questionTallies[game.currentQuestion] = tally;

  io.to(`game:${code}`).emit('question:reveal', { correctIndex: q.correct_index, tally, ranking });
}

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 4000;
server.listen(PORT, () => console.log(`Synapto backend running on port ${PORT}`));
