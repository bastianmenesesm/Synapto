const { DatabaseSync } = require('node:sqlite');
const path = require('path');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'synapto.db');
const db = new DatabaseSync(DB_PATH);

db.exec(`PRAGMA journal_mode = WAL`);

db.exec(`
  CREATE TABLE IF NOT EXISTS quizzes (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS questions (
    id TEXT PRIMARY KEY,
    quiz_id TEXT NOT NULL,
    text TEXT NOT NULL,
    options TEXT NOT NULL,
    correct_index INTEGER NOT NULL,
    time_limit INTEGER DEFAULT 20,
    position INTEGER DEFAULT 0,
    tag TEXT DEFAULT NULL,
    FOREIGN KEY (quiz_id) REFERENCES quizzes(id)
  );
`);
try { db.prepare('ALTER TABLE questions ADD COLUMN tag TEXT DEFAULT NULL').run(); } catch {}

db.exec(`
  CREATE TABLE IF NOT EXISTS evaluations (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    title TEXT NOT NULL,
    time_limit INTEGER NOT NULL DEFAULT 90,
    grade_min REAL DEFAULT 1.0,
    grade_max REAL DEFAULT 7.0,
    pass_percentage INTEGER DEFAULT 60,
    status TEXT DEFAULT 'draft',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS evaluation_questions (
    id TEXT PRIMARY KEY,
    evaluation_id TEXT NOT NULL,
    text TEXT NOT NULL,
    options TEXT NOT NULL,
    correct_index INTEGER NOT NULL,
    position INTEGER DEFAULT 0,
    tag TEXT DEFAULT NULL,
    FOREIGN KEY (evaluation_id) REFERENCES evaluations(id)
  );

  CREATE TABLE IF NOT EXISTS evaluation_submissions (
    id TEXT PRIMARY KEY,
    evaluation_id TEXT NOT NULL,
    student_name TEXT NOT NULL,
    student_rut TEXT NOT NULL,
    answers TEXT NOT NULL DEFAULT '[]',
    question_order TEXT NOT NULL DEFAULT '[]',
    correct_count INTEGER DEFAULT 0,
    total_count INTEGER DEFAULT 0,
    grade REAL DEFAULT NULL,
    submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    time_used INTEGER DEFAULT 0
  );
`);

module.exports = db;
