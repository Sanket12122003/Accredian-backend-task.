const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');

const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.json());

// MySQL Connection
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'student',
});

connection.connect((err) => {
  if (err) {
    console.error('Error connecting to MySQL: ', err);
    return;
  }
  console.log('Connected to MySQL!');
});

// RESTful Endpoints
app.post('/signup', async (req, res) => {
  const { username ,email, password } = req.body;

  // Check if the email already exists
  const emailExists = await checkEmailExists(email);
  if (emailExists) {
    return res.status(400).json({ error: 'Email already exists' });
  }
  

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Insert user into the database
  connection.query(
    'INSERT INTO users (username , email, password) VALUES (?, ?, ?)',
    [username , email, hashedPassword],
    (err, results) => {
      if (err) {
        console.error('Error signing up: ', err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      return res.status(201).json({ message: 'User signed up successfully' });
    }
  );
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Retrieve user from the database
  connection.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) {
      console.error('Error logging in: ', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }

    if (results.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = results[0];

    // Compare the provided password with the hashed password from the database
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    return res.status(200).json({ message: 'Login successful' });
  });
});

// To check if the email already exists
async function checkEmailExists(email) {
  return new Promise((resolve, reject) => {
    connection.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
      if (err) {
        reject(err);
      } else {
        resolve(results.length > 0);
      }
    });
  });
}

// Server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
