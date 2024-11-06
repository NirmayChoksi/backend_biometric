// routes/auth.js
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Temporary in-memory "database" for storing users
const users = [];
const JWT_SECRET = 'your_secret_key'; // Use environment variables in production

// Register route
router.post('/register', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Check if user already exists
        const existingUser = users.find(user => user.email === email);
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Add user to the "database"
        const newUser = { id: users.length + 1, email, password: hashedPassword };
        users.push(newUser);

        res.status(201).json({ message: 'User registered successfully', user: newUser });
    } catch (error) {
        console.log('error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Login route
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Check if user exists
        const user = users.find(user => user.email === email);
        if (!user) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        // Compare password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        // Generate JWT
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({ message: 'Login successful', token });
    } catch (error) {
        console.log('error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

router.post('/validate-token', (req, res) => {
    const { token } = req.body;

    if (!token) {
        return res.status(400).json({ message: 'No token provided' });
    }

    try {
        // Verify the token
        const decoded = jwt.verify(token, JWT_SECRET);  // Replace with your secret key
        res.json({ isValid: true, userId: decoded.userId });
    } catch (err) {
        res.status(401).json({ message: 'Invalid or expired token' });
    }
});

// Middleware to protect routes
function authenticateToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(401).json({ message: 'Access token missing' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

// Protected route example
router.get('/profile', authenticateToken, (req, res) => {
    try {
        res.json({ message: 'This is a protected route', user: req.user });
    } catch (error) {
        console.log('error:', error);
        res.status(500).json({ message: 'Internal server error' })
    }
});

module.exports = router;
