// --- Backend Server Setup (Requires Node.js environment to run) ---
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const otpGenerator = require('otp-generator');
const nodemailer = require('nodemailer'); // For sending OTP emails

// Environment setup (replace with actual MongoDB URI and secret)
const MONGODB_URI = 'mongodb+srv://patelvraj1922_db_user:YUELQad0fcexVnsO@vrajpatel.jwmbqiy.mongodb.net/?appName=vrajpatel';
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
    isVerified: { type: Boolean, default: false }, // OTP verified ho chuka hai ya nahi
    otp: { type: String }, // OTP store karne ke liye
    otpExpiry: { type: Date }, // OTP ka samay
    role: { type: String, enum: ['user', 'admin'], default: 'user' }
});

const User = mongoose.model('User', UserSchema);

// --- Helper Functions ---

// OTP generate aur database mein save karta hai
const generateAndSendOtp = async (user) => {
    const otp = otpGenerator.generate(6, { digits: true, lowerCaseAlphabets: false, upperCaseAlphabets: false, specialChars: false });
    const otpExpiry = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes expiry

    user.otp = otp;
    user.otpExpiry = otpExpiry;
    await user.save();

    // NOTE: Yeh asli email nahi bhejta. Yeh sirf terminal mein OTP print karta hai.
    console.log(`[EMAIL MOCK] New OTP ${otp} sent to ${user.email}`);
    return otp; 
};


// --- API Routes ---

// 1. Register User (Sirf Email aur Password save hoga)
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
            message: 'Registration successful. Please login with your email and password to receive OTP.',
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

// 2. Login User (OTP generation is part of login)
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

        // Generate and send OTP upon successful password match
        await generateAndSendOtp(user);

        res.json({ 
            message: 'Login successful. OTP sent to your email (check terminal).',
            email: user.email 
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

// 3. Resend OTP 
app.post('/api/resend-otp', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }
        
        // Generate and send new OTP
        await generateAndSendOtp(user);

        res.json({ 
            message: 'New OTP sent to your email (check terminal).',
            email: user.email 
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error during OTP resend.' });
    }
});

// 4. Verify OTP and Finalize Login
app.post('/api/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;
        const user = await User.findOne({ email });

        if (!user) return res.status(404).json({ message: 'User not found.' });
        if (!user.otp || user.otp !== otp) {
            return res.status(400).json({ message: 'Invalid OTP. Please check the code or resend.' });
        }
        if (user.otpExpiry < new Date()) {
            return res.status(400).json({ message: 'OTP expired. Please use the login page to resend a new OTP.' });
        }
        
        // OTP is valid
        // user.isVerified = true; // No need to set verified flag, token handles access
        user.otp = undefined; // OTP hatana
        user.otpExpiry = undefined; // Expiry time hatana
        await user.save();

        const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '1d' });
        res.json({ message: 'Login successful. Portfolio access granted.', token, user: { email: user.email, role: user.role } });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error during OTP verification.' });
    }
});

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