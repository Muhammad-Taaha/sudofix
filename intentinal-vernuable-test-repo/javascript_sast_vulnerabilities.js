/**
 * JavaScript SAST Vulnerabilities Demo
 * This file contains intentional security vulnerabilities for testing purposes
 */

const express = require('express');
const { exec } = require('child_process');
const mysql = require('mysql');
const crypto = require('crypto');
const fs = require('fs');

const app = express();

// Vulnerability 1: Hardcoded Credentials
const DB_PASSWORD = 'SuperSecret123!';
const API_SECRET = 'my-api-secret-key-12345';
const AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

// Vulnerability 2: SQL Injection
app.get('/users/:id', (req, res) => {
    const userId = req.params.id;
    // Unsafe SQL query
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    connection.query(query, (error, results) => {
        res.json(results);
    });
});

// Vulnerability 3: Command Injection
app.get('/run', (req, res) => {
    const command = req.query.cmd;
    // Unsafe command execution
    exec(`ls -la ${command}`, (error, stdout, stderr) => {
        res.send(stdout);
    });
});

// Vulnerability 4: Path Traversal
app.get('/download', (req, res) => {
    const filename = req.query.file;
    // No path validation
    res.sendFile(`/var/files/${filename}`);
});

// Vulnerability 5: XSS (Reflected)
app.get('/search', (req, res) => {
    const searchTerm = req.query.q;
    // No output encoding
    res.send(`<h1>Search results for: ${searchTerm}</h1>`);
});

// Vulnerability 6: Insecure Direct Object Reference
app.get('/document/:id', (req, res) => {
    const docId = req.params.id;
    // No authorization check
    const content = fs.readFileSync(`/documents/${docId}.txt`, 'utf8');
    res.send(content);
});

// Vulnerability 7: Weak Cryptography (MD5)
function hashPassword(password) {
    // MD5 is insecure for password hashing
    return crypto.createHash('md5').update(password).digest('hex');
}

// Vulnerability 8: Insecure Random Number Generation
function generateSessionToken() {
    // Math.random() is not cryptographically secure
    return Math.random().toString(36).substring(2);
}

// Vulnerability 9: eval() with user input
app.post('/calculate', (req, res) => {
    const expression = req.body.expr;
    // Never use eval with user input
    const result = eval(expression);
    res.json({ result });
});

// Vulnerability 10: Regular Expression DoS (ReDoS)
app.get('/validate', (req, res) => {
    const input = req.query.data;
    // Vulnerable regex pattern
    const regex = /^(a+)+$/;
    const isValid = regex.test(input);
    res.json({ valid: isValid });
});

// Vulnerability 11: Insecure Cookie Settings
app.get('/login', (req, res) => {
    // Missing secure and httpOnly flags
    res.cookie('sessionId', '12345', { 
        maxAge: 900000
    });
    res.send('Logged in');
});

// Vulnerability 12: Missing CORS Configuration
app.get('/api/sensitive', (req, res) => {
    // Allows requests from any origin
    res.header('Access-Control-Allow-Origin', '*');
    res.json({ secret: 'sensitive data' });
});

// Vulnerability 13: Unvalidated Redirect
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    // No URL validation
    res.redirect(url);
});

// Vulnerability 14: Information Disclosure
app.use((err, req, res, next) => {
    // Exposing stack traces in production
    res.status(500).send(err.stack);
});

// Vulnerability 15: Running with Debug Enabled
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    // Debug mode enabled
    process.env.NODE_ENV = 'development';
});

module.exports = app;
