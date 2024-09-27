const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcryptjs');
const session = require('express-session');

// Create an Express app
const app = express();

// Middleware to parse form data
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files (CSS, images, etc.)
app.use(express.static(path.join(__dirname)));

// Setup session middleware for user login sessions
app.use(session({
    secret: 'yourSecretKey', // Secret key for session
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 60000 } // Session duration (60 minutes)
}));

// MySQL connection setup
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'root',
    database: 'my_website'
});

// Connect to MySQL
db.connect((err) => {
    if (err) {
        throw err;
    }
    console.log('Connected to MySQL database');
});

// Route to serve the login form (with error handling)
app.get('/login', (req, res) => {
    const error = req.query.error ? 'Incorrect credentials, please try again.' : '';
    res.sendFile(path.join(__dirname, 'login.html'));
});

// Handle login submission
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Query to check if the user exists
    const query = `SELECT * FROM users WHERE username = ?`;
    db.query(query, [username], (err, results) => {
        if (err) {
            return res.send('Error occurred: ' + err.message);
        }

        // If user exists, check the password
        if (results.length > 0) {
            const user = results[0];

            // Compare the hashed password with the provided password
            bcrypt.compare(password, user.password, (err, isMatch) => {
                if (err) {
                    return res.send('Error occurred: ' + err.message);
                }

                if (isMatch) {
                    // Successful login
                    req.session.userId = user.id; // Store user id in session
                    res.redirect('/dashboard.html'); // Redirect to dashboard.html
                } else {
                    // Incorrect password
                    res.redirect('/login?error=incorrect'); // Redirect back to login with error message
                }
            });
        } else {
            // No user found
            res.redirect('/login?error=incorrect'); // Redirect back to login with error message
        }
    });
});

// Handle registration submission (optional if you want to keep registration)
app.post('/register', (req, res) => {
    const { username, email, password } = req.body;

    // Hash the password before storing it
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            return res.status(500).send('Error while hashing password');
        }

        // Query to insert a new user with the hashed password
        const query = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
        db.query(query, [username, email, hashedPassword], (err, results) => {
            if (err) {
                return res.status(500).send('Error while registering');
            }
            res.send('Registration successful! Please log in.');
        });
    });
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
