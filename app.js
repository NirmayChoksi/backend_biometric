const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');  // Import cors
const authRoutes = require('./routes/auth');

const app = express();
const PORT = 3000;

// Middleware
app.use(bodyParser.json());

// CORS configuration (allow all origins for simplicity, modify as needed)
app.use(cors()); // This will allow requests from all origins

// For more restricted CORS, specify allowed origins:
app.use(cors());

// Routes
app.use('/api/auth', authRoutes);

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
