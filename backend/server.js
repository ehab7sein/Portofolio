const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');
const path = require('path');

const app = express();
const port = 3000;
const JWT_SECRET = 'portfolio-secret-key-2026'; // In production, use process.env.JWT_SECRET

// Set up lowdb
const adapter = new FileSync(path.join(__dirname, 'db.json'));
const db = low(adapter);

// Initial database structure
db.defaults({ 
  skills: [],
  projects: [],
  experience: [],
  education: [],
  certificates: [],
  users: [
    { 
        username: '01026897739', 
        password: bcrypt.hashSync('01275924043Ee$', 10) 
    }
  ]
}).write();

app.use(cors({
    origin: true,
    credentials: true
}));
app.use(bodyParser.json());
app.use(cookieParser());

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const token = req.cookies.auth_token;
    
    if (!token) {
        if (req.path.startsWith('/api/')) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        return res.redirect('/login');
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            res.clearCookie('auth_token');
            if (req.path.startsWith('/api/')) {
                return res.status(403).json({ error: 'Forbidden' });
            }
            return res.redirect('/login');
        }
        req.user = user;
        next();
    });
};

// Log all requests
app.use((req, res, next) => {
    console.log(`${req.method} ${req.url}`);
    next();
});

// Auth Routes
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = db.get('users').find({ username }).value();

    if (user && bcrypt.compareSync(password, user.password)) {
        const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '24h' });
        res.cookie('auth_token', token, {
            httpOnly: true,
            secure: false, // Set to true in production with HTTPS
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });
        return res.json({ success: true });
    }

    res.status(401).json({ error: 'Invalid credentials' });
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('auth_token');
    res.json({ success: true });
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

// Protected Admin Dashboard
app.get('/admin', authenticateToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'admin.html'));
});

// API Routes
const resources = ['skills', 'projects', 'experience', 'education', 'certificates'];

resources.forEach(resource => {
    // GET remains public for the portfolio website
    app.get(`/api/${resource}`, (req, res) => {
        const data = db.get(resource).value();
        res.json(data || []);
    });

    // POST, PUT, DELETE are protected
    app.post(`/api/${resource}`, authenticateToken, (req, res) => {
        const item = { id: Date.now(), ...req.body };
        db.get(resource).push(item).write();
        res.status(201).json(item);
    });

    app.put(`/api/${resource}/:id`, authenticateToken, (req, res) => {
        const id = parseInt(req.params.id);
        db.get(resource)
          .find({ id })
          .assign(req.body)
          .write();
        res.json({ success: true });
    });

    app.delete(`/api/${resource}/:id`, authenticateToken, (req, res) => {
        db.get(resource).remove({ id: parseInt(req.params.id) }).write();
        res.status(204).send();
    });
});

// Serve Static Files (except admin.html and login.html which are handled above)
app.use(express.static(path.join(__dirname, 'public')));

if (process.env.NODE_ENV !== 'production') {
    app.listen(port, () => {
      console.log(`Portfolio Backend running at http://localhost:${port}`);
      console.log(`Admin Dashboard: http://localhost:${port}/admin`);
    });
}

module.exports = app;