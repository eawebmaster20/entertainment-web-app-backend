const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cors= require('cors');
const path = require('path'); 
const fs = require('fs'); 
const helmet = require('helmet');

dotenv.config();

const app = express();
app.use(bodyParser.json());
app.use(helmet());
app.use(cors());

const db = new sqlite3.Database('./auth.db', (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to SQLite database.');
   db.run(
      `CREATE TABLE IF NOT EXISTS users (
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         username TEXT UNIQUE,
         password TEXT
       )`,
      (err) => {
        if (err) {
          console.error('Error creating users table:', err.message);
        }
      }
    );
  }
});

app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
    console.log(req.body);
  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, row) => {
    if (err) {
      return res.status(500).json({ error: 'Server error' });
    }
    if (row) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);
    db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hashedPassword], (err) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to register user' });
      }
      res.status(201).json({ message: 'User registered successfully' });
    });
  });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  console.log(req.body);
  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Server error' });
    }
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isMatch = bcrypt.compareSync(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  });
});

app.get('/api/movies', (req, res) => {
    console.log(req.body);
  const token = req.headers['authorization'];
  if (!token) {
    return res.status(403).json({ message: 'No token provided' });
  }

  jwt.verify(token.split(' ')[1], process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(500).json({ message: 'Failed to authenticate token' });
    }
    db.get(`SELECT id, username FROM users WHERE id = ?`, [decoded.id], (err, user) => {
      if (err || !user) {
        return res.status(404).json({ message: 'User not found' });
      }
      const filePath = path.join(__dirname, 'data.json');

        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Transfer-Encoding', 'chunked');  

        const readStream = fs.createReadStream(filePath, { encoding: 'utf8' });

        readStream.pipe(res);

        readStream.on('error', (err) => {
            console.error('Error reading the file:', err);
            res.status(500).send('Server error occurred');
        });

        readStream.on('end', () => {
            res.end();
        });
    });
  });
});


const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
