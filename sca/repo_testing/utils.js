const _ = require('lodash');
const React = require('react');
const express = require('express');
const sqlite3 = require('sqlite3');

// Vulnerable: Using dangerouslySetInnerHTML - XSS vulnerability
const UserProfile = (props) => {
  return (
    <div>
      <h1>User Profile</h1>
      {/* VULNERABLE: dangerouslySetInnerHTML allows XSS attacks */}
      <div dangerouslySetInnerHTML={{ __html: props.userBio }} />
      <p dangerouslySetInnerHTML={{ __html: props.description }} />
    </div>
  );
};

// Vulnerable: SQL Injection via string concatenation
const app = express();
app.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  // VULNERABLE: Direct string concatenation in SQL query
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  db.all(query, (err, rows) => {
    res.json(rows);
  });
});

// Vulnerable: Using eval() - Code injection
function processData(data) {
  // VULNERABLE: eval can execute arbitrary code
  return eval(data);
}

// Vulnerable: Unsafe use of innerHTML
function updateContent(userContent) {
  // VULNERABLE: innerHTML can execute injected scripts
  document.getElementById('content').innerHTML = userContent;
}

// Vulnerable: Using Function constructor
function executeUserCode(code) {
  // VULNERABLE: Function constructor can execute arbitrary code
  return new Function(code)();
}

// Vulnerable: Weak crypto (using Math.random)
function generateSessionToken() {
  // VULNERABLE: Math.random is not cryptographically secure
  return Math.random().toString(36).substring(2, 15);
}

// Vulnerable: Hardcoded secrets
const API_KEY = 'sk-1234567890abcdefghijklmnop';
const DB_PASSWORD = 'admin123456';
const JWT_SECRET = 'super-secret-key';

// Vulnerable: XSS in setAttribute
app.get('/link/:url', (req, res) => {
  const url = req.query.url;
  // VULNERABLE: User input directly in HTML attribute
  res.send(`<a href="${url}">Click here</a>`);
});

// Vulnerable: Using JSON.parse without validation
app.post('/data', (req, res) => {
  try {
    // VULNERABLE: No input validation before JSON.parse
    const data = JSON.parse(req.body);
    res.json(data);
  } catch (e) {
    res.status(400).send('Invalid JSON');
  }
});

console.log(_.VERSION);