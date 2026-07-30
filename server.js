const express = require('express');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_USERNAME = 'iamanteneh'; // Your verified username

// Middleware to parse JSON and static files
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// 1. Telegram Security Verification Middleware
function verifyTelegramAuth(req, res, next) {
    const initData = req.headers['x-telegram-init-data'];
    const botToken = process.env.TELEGRAM_BOT_TOKEN;

    if (!initData) {
        return res.status(401).json({ error: 'Access Denied: No credentials provided.' });
    }

    try {
        const urlParams = new URLSearchParams(initData);
        const hash = urlParams.get('hash');
        urlParams.delete('hash');

        const dataCheckString = Array.from(urlParams.entries())
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([key, val]) => `${key}=${val}`)
            .join('\n');

        const secretKey = crypto.createHmac('sha256', 'WebAppData').update(botToken).digest();
        const calculatedHash = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');

        if (calculatedHash !== hash) {
            return res.status(403).json({ error: 'Access Denied: Invalid signature.' });
        }

        const user = JSON.parse(urlParams.get('user'));
        
        // Strict ownership check
        if (user.username !== ADMIN_USERNAME) {
            return res.status(403).json({ error: 'Access Denied: Unauthorized account.' });
        }

        next();
    } catch (err) {
        return res.status(400).json({ error: 'Invalid authentication payload.' });
    }
}

// 2. Admin API Endpoint for Dashboard Metrics
app.get('/admin/api/dashboard', verifyTelegramAuth, (req, res) => {
    res.json({
        totalVisitors: 1250,
        visitorsToday: 42,
        visitorsWeek: 310,
        visitorsMonth: 1120,
        returningVisitors: 340,
        onlineVisitors: 5
    });
});

// 3. Serve the Admin Dashboard Page Securely
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
