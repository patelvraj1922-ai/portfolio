// --- Backend Server Setup (Requires Node.js environment to run) ---
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
// const otpGenerator = require('otp-generator'); // REMOVED
// const nodemailer = require('nodemailer'); // REMOVED

// Environment setup (replace with actual MongoDB URI and secret)
// Note: User provided the complete URL with 'jwmbqiy' cluster name, but without the database name.
const MONGODB_URI = 'mongodb+srv://patelvraj1922_db_user:YUELQad0fcexVnsO@vrajpatel.jwmbqiy.mongodb.net/vraj_portfolio?retryWrites=true&w=majority';
const JWT_SECRET = 'YOUR_SUPER_SECRET_KEY_12345';
const PORT = process.env.PORT || 3000;

const app = express();

// Middleware
app.use(cors()); // Allows the client-side HTML to communicate with this server
app.use(express.json());

// --- Database Connection ---
mongoose.connect(MONGODB_URI)
  .then(() => console.log('MongoDB connected successfully'))
  .catch(err => console.error('MongoDB connection error:', err));

// --- User Schema and Model ---
const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    // OTP fields are removed since OTP is no longer used
    role: { type: String, enum: ['user', 'admin'], default: 'user' }
});

const User = mongoose.model('User', UserSchema);

// --- API Routes ---

// 1. Register User (Email and Password save hoga)
app.post('/api/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Email already registered. Please proceed to login.' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Check if the user is the designated admin
        const userRole = (email.toLowerCase() === 'patelvraj1922@gmail.com') ? 'admin' : 'user';

        const user = new User({ email, password: hashedPassword, role: userRole });
        await user.save();

        res.status(201).json({ 
            message: 'Registration successful. Please login with your email and password.',
            email: user.email
        });

    } catch (error) {
        if (error.code === 11000) {
            return res.status(400).json({ message: 'Email already registered.' });
        }
        console.error(error);
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

// 2. Login User (Directly authenticates with password and returns token)
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ message: 'User not found. Please register first.' });
        }
        
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials. Password does not match.' });
        }

        // Authentication successful, generate token
        const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '1d' });

        res.json({ 
            message: 'Login successful. Portfolio access granted.',
            token, 
            user: { email: user.email, role: user.role } 
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

// Resend OTP route is removed

// Verify OTP route is removed

// Admin Route Example (Requires Authentication Middleware)
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

const isAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access denied: Admin role required.' });
    }
    next();
};

app.get('/api/admin/dashboard', authenticateToken, isAdmin, (req, res) => {
    res.json({ message: `Welcome Admin, ${req.user.id}.`, data: 'Secret admin data here.' });
});


// Start Server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});