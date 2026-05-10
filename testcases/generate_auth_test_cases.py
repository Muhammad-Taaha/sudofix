import os

BASE = "test_cases_for_sast/auth"

test_cases = {
    "hardcoded_password": {
        "vulnerable.py": """
# Hardcoded password in Python
PASSWORD = "super_secret_123"   # DANGEROUS
db_password = "admin123"
""",
        "safe.py": """
import os
PASSWORD = os.environ.get("DB_PASSWORD")   # SAFE
db_password = os.getenv("DB_PASS")
""",
        "vulnerable.java": """
public class Config {
    String PASSWORD = "admin123";   // DANGEROUS
}
""",
        "safe.java": """
public class Config {
    String PASSWORD = System.getenv("DB_PASSWORD");
}
""",
        "vulnerable.js": """
// Hardcoded password in JavaScript
const PASSWORD = "super_secret_123";   // DANGEROUS
let dbPass = "admin123";
""",
        "safe.js": """
const PASSWORD = process.env.DB_PASSWORD;   // SAFE
let dbPass = process.env.DB_PASS;
""",
        "vulnerable.go": """
package main
func main() {
    password := "super_secret_123"   // DANGEROUS
}
""",
        "safe.go": """
package main
import "os"
func main() {
    password := os.Getenv("DB_PASSWORD")   // SAFE
}
""",
        "README.md": "# Hardcoded Password Test Cases",
    },
    "hardcoded_api_key": {
        "vulnerable.py": """
API_KEY = "abc123def456ghi789"   # DANGEROUS
SECRET_KEY = "my-secret-key"
""",
        "safe.py": """
import os
API_KEY = os.environ.get("API_KEY")
SECRET_KEY = os.getenv("SECRET_KEY")
""",
        "vulnerable.java": """
public class Keys {
    String API_KEY = "abc123";   // DANGEROUS
}
""",
        "safe.java": """
public class Keys {
    String API_KEY = System.getenv("API_KEY");
}
""",
        "vulnerable.js": """
const API_KEY = "abc123def456";   // DANGEROUS
let token = "my_token";
""",
        "safe.js": """
const API_KEY = process.env.API_KEY;
let token = process.env.TOKEN;
""",
        "vulnerable.go": """
package main
func main() {
    apiKey := "abc123def456"   // DANGEROUS
}
""",
        "safe.go": """
package main
import "os"
func main() {
    apiKey := os.Getenv("API_KEY")
}
""",
        "README.md": "# Hardcoded API Key Test Cases",
    },
    "weak_password_hash": {
        "vulnerable.py": """
import hashlib
password = "secret"
hash_md5 = hashlib.md5(password.encode()).hexdigest()   # DANGEROUS
hash_sha1 = hashlib.sha1(password.encode()).hexdigest()
""",
        "safe.py": """
import hashlib
password = "secret"
hash_sha256 = hashlib.sha256(password.encode()).hexdigest()   # SAFE
from passlib.hash import bcrypt
bcrypt.hash(password)
""",
        "vulnerable.java": """
import java.security.MessageDigest;
MessageDigest md5 = MessageDigest.getInstance("MD5");   // DANGEROUS
MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
""",
        "safe.java": """
MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
""",
        "vulnerable.js": """
const crypto = require('crypto');
const hash = crypto.createHash('md5').update('secret').digest('hex');   // DANGEROUS
""",
        "safe.js": """
const crypto = require('crypto');
const hash = crypto.createHash('sha256').update('secret').digest('hex');
""",
        "vulnerable.go": """
package main
import "crypto/md5"
hash := md5.Sum([]byte("secret"))   // DANGEROUS
""",
        "safe.go": """
import "crypto/sha256"
hash := sha256.Sum256([]byte("secret"))
""",
        "README.md": "# Weak Password Hash Test Cases",
    },
    "session_fixation": {
        "vulnerable.py": """
# Flask vulnerable login
@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form['user'])
    session['user_id'] = user.id   # DANGEROUS (no session regeneration)
    return redirect('/dashboard')
""",
        "safe.py": """
@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form['user'])
    session.clear()
    session.regenerate()   # or request.session.cycle_key()
    session['user_id'] = user.id
    return redirect('/dashboard')
""",
        "vulnerable.java": """
@PostMapping("/login")
public String login(HttpServletRequest request) {
    User user = authService.authenticate(request.getParameter("user"));
    request.getSession().setAttribute("user", user);   // DANGEROUS
    return "redirect:/dashboard";
}
""",
        "safe.java": """
@PostMapping("/login")
public String login(HttpServletRequest request) {
    User user = authService.authenticate(request.getParameter("user"));
    request.changeSessionId();   // SAFE
    request.getSession().setAttribute("user", user);
    return "redirect:/dashboard";
}
""",
        "vulnerable.js": """
// Express vulnerable login
app.post('/login', (req, res) => {
    const user = authenticate(req.body.user);
    req.session.user = user;   // DANGEROUS (no regeneration)
    res.redirect('/dashboard');
});
""",
        "safe.js": """
app.post('/login', (req, res) => {
    const user = authenticate(req.body.user);
    req.session.regenerate(() => {   // SAFE
        req.session.user = user;
        res.redirect('/dashboard');
    });
});
""",
        "vulnerable.go": """
// Gin framework
func login(c *gin.Context) {
    user := authenticate(c.PostForm("user"))
    session.Set("user", user)   // DANGEROUS (no regeneration)
    c.Redirect(302, "/dashboard")
}
""",
        "safe.go": """
func login(c *gin.Context) {
    user := authenticate(c.PostForm("user"))
    session.Regenerate()   // SAFE
    session.Set("user", user)
    c.Redirect(302, "/dashboard")
}
""",
        "README.md": "# Session Fixation Test Cases",
    },
    "missing_auth_decorator": {
        "vulnerable.py": """
# Flask view without login decorator
@app.route('/admin')
def admin_panel():
    return "Admin content"   # DANGEROUS (no @login_required)
""",
        "safe.py": """
from flask_login import login_required
@app.route('/admin')
@login_required
def admin_panel():
    return "Admin content"
""",
        "vulnerable.java": """
@GetMapping("/admin")
public String adminPanel() {   // DANGEROUS (no @PreAuthorize)
    return "admin";
}
""",
        "safe.java": """
@GetMapping("/admin")
@PreAuthorize("hasRole('ADMIN')")
public String adminPanel() {
    return "admin";
}
""",
        "vulnerable.js": """
// Express route without auth middleware
app.get('/admin', (req, res) => {
    res.send('admin');   // DANGEROUS
});
""",
        "safe.js": """
const ensureAuth = (req, res, next) => { if (req.isAuthenticated()) return next(); res.redirect('/login'); };
app.get('/admin', ensureAuth, (req, res) => {
    res.send('admin');
});
""",
        "vulnerable.go": """
// Gin route without auth middleware
r.GET("/admin", func(c *gin.Context) {
    c.String(200, "admin")   // DANGEROUS
})
""",
        "safe.go": """
r.GET("/admin", AuthRequired(), func(c *gin.Context) {
    c.String(200, "admin")
})
""",
        "README.md": "# Missing Authentication Decorator Test Cases",
    },
}

def create_test_cases():
    for rule, files in test_cases.items():
        rule_dir = os.path.join(BASE, rule)
        os.makedirs(rule_dir, exist_ok=True)
        for filename, content in files.items():
            filepath = os.path.join(rule_dir, filename)
            with open(filepath, "w") as f:
                f.write(content.lstrip())
        print(f"Created {rule_dir}")

if __name__ == "__main__":
    create_test_cases()
    print("Auth test cases generated successfully.")