const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const cors = require("cors");

const app = express();
const PORT = 3000;
const SECRET_KEY = "supersecretkey"; // change in real world

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Database
const db = new sqlite3.Database("./finance.db");

// Create tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    type TEXT,  -- 'income' or 'expense'
    amount REAL,
    note TEXT,
    date TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});

// ✅ Register user
app.post("/register", (req, res) => {
  const { username, password } = req.body;
  const hashed = bcrypt.hashSync(password, 8);

  db.run(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    [username, hashed],
    function (err) {
      if (err) return res.status(400).json({ error: "User already exists" });
      res.json({ message: "User registered successfully" });
    }
  );
});

// ✅ Login user
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (!user) return res.status(400).json({ error: "User not found" });

    const valid = bcrypt.compareSync(password, user.password);
    if (!valid) return res.status(401).json({ error: "Invalid password" });

    const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: "1h" });
    res.json({ token });
  });
});

// Middleware to verify JWT
function verifyToken(req, res, next) {
  const bearer = req.headers["authorization"];
  if (!bearer) return res.status(403).json({ error: "No token provided" });

  const token = bearer.split(" ")[1];
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ error: "Unauthorized" });
    req.userId = decoded.id;
    next();
  });
}

// ✅ Add transaction
app.post("/transaction", verifyToken, (req, res) => {
  const { type, amount, note, date } = req.body;
  db.run(
    "INSERT INTO transactions (user_id, type, amount, note, date) VALUES (?, ?, ?, ?, ?)",
    [req.userId, type, amount, note, date],
    function (err) {
      if (err) return res.status(500).json({ error: "Failed to add transaction" });
      res.json({ message: "Transaction added" });
    }
  );
});

// ✅ Get user transactions
app.get("/transactions", verifyToken, (req, res) => {
  db.all("SELECT * FROM transactions WHERE user_id = ?", [req.userId], (err, rows) => {
    if (err) return res.status(500).json({ error: "Failed to fetch" });
    res.json(rows);
  });
});

// Start server
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
