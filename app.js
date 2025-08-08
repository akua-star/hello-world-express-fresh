const express = require('express');
const { Sequelize, DataTypes } = require('sequelize');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// Database Configuration (use environment variables from Render)
const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'postgres',
  protocol: 'postgres',
  logging: false, // Set to console.log for debugging if needed
});

// Define User Model
const User = sequelize.define('user', {
  id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  username: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  encryption_key: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  created_at: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW,
  },
});

// Sync Model with Database (create table if it doesn't exist)
(async () => {
  try {
    await sequelize.sync({ alter: true }); // Use { force: true } only for testing to drop and recreate
    console.log('Database synced');
  } catch (err) {
    console.error('Database sync error:', err);
  }
})();

// Signup Endpoint
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Missing required fields (username, email, password)' });
    }
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const encryptionKey = crypto.randomBytes(16).toString('hex');
    const user = await User.create({ username, email, password: hashedPassword, encryption_key: encryptionKey });
    res.status(201).json({ message: 'User created', user: { id: user.id, username: user.username, email: user.email } });
  } catch (err) {
    console.error('Signup error details:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login Endpoint
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    if (!username || !password) {
      return res.status(400).json({ error: 'Missing required fields (username, password)' });
    }
    const user = await User.findOne({ where: { username } });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = crypto.randomBytes(16).toString('hex'); // Simple token for demo
    res.status(200).json({ message: 'Login successful', token });
  } catch (err) {
    console.error('Login error details:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Start Server
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;