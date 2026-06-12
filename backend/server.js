const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const QRCode = require('qrcode');
const { v4: uuidv4 } = require('uuid');
const db = require('./db');

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

app.use(cors());
app.use(express.json());

// ─── In-memory game state ────────────────────────────────────────────────────
const games = {}; // gameCode → gameState

function createGameState(quizId) {
  return {
    quizId,
    status: 'lobby',       // lobby | question | results | finished
    currentQuestion: -1,
    players: {},           // socketId → { name, score, answered }
    questionTimer: null,
    timeLeft: 0,
  };
}

// ─── REST API ────────────────────────────────────────────────────────────────

// Health check
app.get('/api/health', (req, res) => res.json({ ok: true }));

// Get all quizzes
app.get('/api/quizzes', (req, res) => {
  const quizzes = db.prepare('SELECT * FROM quizzes ORDER BY created_at DESC').all();
  res.json(quizzes);
});

// Get quiz with questions
app.get('/api/quizzes/:id', (req, res) => {
  const quiz = db.prepare('SELECT * FROM quizzes WHERE id = ?').get(req.params.id);
  if (!quiz) return res.status(404).json({ error: 'Quiz no encontrado' });
  const questions = db.prepare('SELECT * FROM questions WHERE quiz_id = ? ORDER BY position').all(quiz.id);
  questions.forEach(q => {
    q.options = JSON.parse(q.options);
  });
  res.json({ ...quiz, questions });
});

// Create quiz
app.post('/api/quizzes', (req, res) => {
  const { title, questions } = req.body;
  if (!title || !questions?.length) return res.status(400).json({ error: 'Título y preguntas requeridos' });

  const id = uuidv4();
  db.prepare('INSERT INTO quizzes (id, title) VALUES (?, ?)').run(id, title);

  const insertQ = db.prepare(`
    INSERT INTO questions (id, quiz_id, text, options, correct_index, time_limit, position)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  questions.forEach((q, i) => {
    insertQ.run(uuidv4(), id, q.text, JSON.stringify(q.options), q.correctIndex, q.timeLimit || 20, i);
  });

  res.json({ id });
});

// Update quiz
app.put('/api/quizzes/:id', (req, res) => {
  const { title, questions } = req.body;
  const quiz = db.prepare('SELECT * FROM quizzes WHERE id = ?').get(req.params.id);
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

// Delete quiz
app.delete('/api/quizzes/:id', (req, res) => {
  db.prepare('DELETE FROM questions WHERE quiz_id = ?').run(req.params.id);
  db.prepare('DELETE FROM quizzes WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// Create game session (returns game code + QR)
app.post('/api/games', async (req, res) => {
  const { quizId, baseUrl } = req.body;
  const quiz = db.prepare('SELECT * FROM quizzes WHERE id = ?').get(quizId);
  if (!quiz) return res.status(404).json({ error: 'Quiz no encontrado' });

  const code = Math.random().toString(36).substring(2, 8).toUpperCase();
  const joinUrl = `${baseUrl || process.env.FRONTEND_URL || 'http://localhost:3000'}/player?code=${code}`;

  const qrDataUrl = await QRCode.toDataURL(joinUrl, {
    width: 300,
    margin: 2,
    color: { dark: '#1a1a2e', light: '#ffffff' }
  });

  games[code] = createGameState(quizId);
  games[code].joinUrl = joinUrl;

  res.json({ code, joinUrl, qr: qrDataUrl });
});

// Get game state (for reconnects)
app.get('/api/games/:code', (req, res) => {
  const game = games[req.params.code];
  if (!game) return res.status(404).json({ error: 'Sala no encontrada' });
  res.json({
    status: game.status,
    playerCount: Object.keys(game.players).length,
    joinUrl: game.joinUrl
  });
});

// ─── WebSocket ───────────────────────────────────────────────────────────────

io.on('connection', (socket) => {

  // Admin joins room
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

  // Player joins
  socket.on('player:join', ({ code, name }) => {
    const game = games[code];
    if (!game) return socket.emit('error', 'Sala no encontrada');
    if (game.status !== 'lobby') return socket.emit('error', 'El juego ya comenzó');
    if (!name?.trim()) return socket.emit('error', 'Nombre requerido');

    const playerName = name.trim().substring(0, 20);
    game.players[socket.id] = { name: playerName, score: 0, answered: false };
    socket.join(`game:${code}`);
    socket.gameCode = code;
    socket.role = 'player';

    socket.emit('player:joined', { name: playerName });
    io.to(`game:${code}`).emit('lobby:update', {
      players: Object.values(game.players).map(p => ({ name: p.name, score: p.score }))
    });
  });

  // Screen joins (projector view)
  socket.on('screen:join', ({ code }) => {
    const game = games[code];
    if (!game) return socket.emit('error', 'Sala no encontrada');
    socket.join(`game:${code}`);
    socket.gameCode = code;
    socket.role = 'screen';
    socket.emit('screen:state', {
      status: game.status,
      players: Object.values(game.players).map(p => ({ name: p.name, score: p.score })),
      joinUrl: game.joinUrl
    });
  });

  // Admin: start game / next question
  socket.on('admin:next', () => {
    const code = socket.gameCode;
    const game = games[code];
    if (!game || socket.role !== 'admin') return;

    const questions = db.prepare('SELECT * FROM questions WHERE quiz_id = ? ORDER BY position').all(game.quizId);
    game.currentQuestion++;

    if (game.currentQuestion >= questions.length) {
      // Game over
      game.status = 'finished';
      clearInterval(game.questionTimer);
      const ranking = Object.values(game.players)
        .sort((a, b) => b.score - a.score)
        .map((p, i) => ({ rank: i + 1, name: p.name, score: p.score }));
      io.to(`game:${code}`).emit('game:finished', { ranking });
      return;
    }

    const q = questions[game.currentQuestion];
    q.options = JSON.parse(q.options);
    game.status = 'question';
    game.timeLeft = q.time_limit;

    // Reset answered flag for all players
    Object.values(game.players).forEach(p => { p.answered = false; p.lastAnswer = null; });

    const questionPayload = {
      index: game.currentQuestion,
      total: questions.length,
      text: q.text,
      options: q.options,
      timeLimit: q.time_limit
    };

    io.to(`game:${code}`).emit('question:start', questionPayload);

    // Timer
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

  // Player answers
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
    }

    socket.emit('player:answer:result', {
      correct,
      correctIndex: q.correct_index,
      score: player.score
    });

    // Check if all players answered
    const allAnswered = Object.values(game.players).every(p => p.answered);
    if (allAnswered) {
      clearInterval(game.questionTimer);
      revealAnswers(code, q);
    }
  });

  // Admin skip timer
  socket.on('admin:reveal', () => {
    const code = socket.gameCode;
    const game = games[code];
    if (!game || socket.role !== 'admin') return;
    clearInterval(game.questionTimer);
    const questions = db.prepare('SELECT * FROM questions WHERE quiz_id = ? ORDER BY position').all(game.quizId);
    revealAnswers(code, questions[game.currentQuestion]);
  });

  // Disconnect
  socket.on('disconnect', () => {
    const code = socket.gameCode;
    if (!code || !games[code]) return;
    const game = games[code];
    if (socket.role === 'player') {
      delete game.players[socket.id];
      io.to(`game:${code}`).emit('lobby:update', {
        players: Object.values(game.players).map(p => ({ name: p.name, score: p.score }))
      });
    }
  });
});

function revealAnswers(code, q) {
  const game = games[code];
  if (!game) return;
  game.status = 'results';

  const options = typeof q.options === 'string' ? JSON.parse(q.options) : q.options;
  const tally = options.map((_, i) =>
    Object.values(game.players).filter(p => p.lastAnswer === i).length
  );

  const ranking = Object.values(game.players)
    .sort((a, b) => b.score - a.score)
    .slice(0, 5)
    .map((p, i) => ({ rank: i + 1, name: p.name, score: p.score }));

  io.to(`game:${code}`).emit('question:reveal', {
    correctIndex: q.correct_index,
    tally,
    ranking
  });
}

// ─── Start ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 4000;
server.listen(PORT, () => console.log(`Synapto backend running on port ${PORT}`));
