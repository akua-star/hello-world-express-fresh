const express = require('express');
const { Pool } = require('pg');
const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

// Database configuration for Render
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Local fallback (optional, remove if not needed)
if (!process.env.DATABASE_URL) {
  pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'myexpressdb',
    password: '5432',
    port: 5432,
    ssl: false
  });
}

// Signup API
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO users (username, email, password, created_at) VALUES ($1, $2, $3, NOW()) RETURNING *',
      [username, email, password]
    );
    res.json({ message: 'User created', user: result.rows[0] });
  } catch (err) {
    console.error(err.stack);
    res.status(500).json({ error: 'Error creating user' });
  }
});

// Login API
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE username = $1 AND password = $2',
      [username, password]
    );
    if (result.rows.length > 0) {
      res.json({ message: 'Login successful', user: result.rows[0] });
    } else {
      res.status(401).json({ error: 'Invalid username or password' });
    }
  } catch (err) {
    console.error(err.stack);
    res.status(500).json({ error: 'Error during login' });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

module.exports = app;