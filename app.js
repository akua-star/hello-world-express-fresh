require('dotenv').config();
const express = require('express');
const { Sequelize, DataTypes } = require('sequelize');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

const sequelize = new Sequelize(process.env.DATABASE_URL || `postgres://postgres:5432@localhost:5432/myexpressdb`, {
  dialect: 'postgres',
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

const User = require('./models/user')(sequelize, DataTypes);

//sequelize.sync().then(() => console.log('Database synced')).catch(err => console.error('Sync error:', err.stack));

async function generateJWT(userId) {
  return new Promise((resolve, reject) => {
    jwt.sign({ id: userId }, process.env.JWT_SECRET || 'tempsecret', { algorithm: 'HS256' }, (err, token) => {
      if (err) reject(err);
      else resolve(token);
    });
  });
}

app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    console.log('Received signup data:', req.body); // Log full request body
    console.log('Signup attempt:', { username, email });
    if (!email || !username || !password) {
      return res.status(400).json({ error: 'Missing required fields (username, email, password)' });
    }
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      console.log('Existing user found:', existingUser.toJSON());
      return res.status(400).json({ error: 'Email already exists' });
    }
    console.log('No existing user, proceeding to create');
    const hashedPassword = await bcrypt.hash(password, 10);
    const encryption_key = Math.random().toString(36).substring(2, 15); // Temporary key
    const user = await User.create({ username, email, password: hashedPassword, encryption_key });
    console.log('User created:', user.toJSON());
    res.status(201).json({ message: 'User created', user });
  } catch (err) {
    console.error('Signup error details:', {
      message: err.message,
      stack: err.stack,
      code: err.code
    });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login API
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    console.log('Login attempt:', { username });
    const user = await User.findOne({ where: { username } });
    if (!user) {
      console.log('User not found:', username);
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    console.log('User found:', user.toJSON());
    if (await bcrypt.compare(password, user.password)) {
      const token = await generateJWT(user.id);
      res.json({ message: 'Login successful', token });
    } else {
      console.log('Password mismatch for:', username);
      res.status(401).json({ error: 'Invalid username or password' });
    }
  } catch (err) {
    console.error('Login error details:', {
      message: err.message,
      stack: err.stack,
      code: err.code
    });
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

module.exports = app;