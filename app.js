const express = require('express');
const mysql = require('mysql');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const { escape } = require('mysql');

const app = express();
const port = 3000;
const jwtSecretKey = '3a2a537576392c0fa9974fe3e73f0678';

app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public')); // Serve static files

// MySQL connection
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'REDACTED', // replace with your MySQL username
  password: 'REDACTED', // replace with your MySQL password
  database: 'express_db'
});

connection.connect(err => {
  if (err) throw err;
  console.log("Connected to MySQL database!");
});

// Registration Page
app.get('/register', (req, res) => {
  res.send(`
 <div class="welcome-box">
      <h2>Register a New Account</h2>
      <p>Click <a href="/login">here</a> to go back to log in.</p>

    <link rel="stylesheet" type="text/css" href="style.css">
    <form action="/register" method="post">
      <input type="text" name="username" placeholder="Username" required />
      <input type="password" name="password" placeholder="Password" required />
      <button type="submit">Register</button>
    </form>
  `);
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  bcrypt.hash(password, 10, function(err, hash) {
    if (err) {
      res.status(500).send('Error encrypting password');
    } else {
      const query = 'INSERT INTO auth_table (username, md5pass, role) VALUES (?, ?, 0)';
      connection.query(query, [username, hash], function(error, results, fields) {
        if (error) throw error;
        res.redirect('/login');
      });
    }
  });
});

// Login Page
app.get('/login', (req, res) => {
res.cookie('jwt_id', '', { expires: new Date(0) });
  res.send(`
<link rel="stylesheet" type="text/css" href="style.css">
    <div class="welcome-box">
      <h2>Welcome to my totally awesome express app</h2>
      <p>Click <a href="/login">here</a> to log in.</p>
    </div>
    <form action="/login" method="post">
      <input type="text" name="username" placeholder="Username" required />
      <input type="password" name="password" placeholder="Password" required />
      <button type="submit">Login</button>
    </form>
    <p class="register-link">Don't have an account? <a href="/register">Register here</a></p>
  `);
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const query = 'SELECT * FROM auth_table WHERE username = ?';
  connection.query(query, [username], function(error, results, fields) {
    if (error) throw error;
    if (results.length > 0) {
      bcrypt.compare(password, results[0].md5pass, function(err, result) {
        if (result) {
          const token = jwt.sign({ username: username, user_id: results[0].userid }, jwtSecretKey);
          res.cookie('jwt_id', token, { httpOnly: true });
          res.redirect('/create');
        } else {
          res.send('Incorrect Username and/or Password!');
        }
      });
    } else {
      res.send('Incorrect Username and/or Password!');
    }
  });
});

// Note Creation Page
app.get('/create', (req, res) => {
  const token = req.cookies.jwt_id;
  if (!token) {
    return res.status(401).send('Access Denied');
  }

  try {
    jwt.verify(token, jwtSecretKey);
    const verified = jwt.verify(token, jwtSecretKey);
    res.send(`
      <link rel="stylesheet" type="text/css" href="style.css">
 <div class="welcome-box">
      <h2>Hello ${verified.username}. Create a note!</h2>
      <p>Click <a href="/view">here</a> to view your notes.</p>

      <form action="/create" method="post">
        <textarea name="note" placeholder="Type your note"></textarea>
        <button type="submit">Submit Note</button>
      </form>
    `);
  } catch (error) {
    res.status(400).send('Invalid Token');
  }
});

app.post('/create', (req, res) => {
  const token = req.cookies.jwt_id;
  if (!token) {
    return res.status(401).send('Access Denied');
  }

  try {
    const verified = jwt.verify(token, jwtSecretKey);
    const note = escape(req.body.note);
    const query = 'INSERT INTO notes_table (user_id, note_content) VALUES (?, ?)';
    connection.query(query, [verified.user_id, note], (error, results, fields) => {
      if (error) throw error;
      res.redirect('/view');
    });
  } catch (error) {
    res.status(400).send('Invalid Token');
  }
});

// View Notes Page
app.get('/view', (req, res) => {
  const token = req.cookies.jwt_id;
  if (!token) {
    return res.status(401).send('Access Denied');
  }

  try {
    const verified = jwt.verify(token, jwtSecretKey);
    const query = 'SELECT note_content FROM notes_table WHERE user_id = ?';
    connection.query(query, [verified.user_id], (error, results, fields) => {
      if (error) throw error;
      const notes = results.map(row => `<li>${row.note_content}</li>`).join('');
      res.send(`
        <link rel="stylesheet" type="text/css" href="style.css">
        <ul>${notes}</ul>
      `);
    });
  } catch (error) {
    res.status(400).send('Invalid Token');
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
