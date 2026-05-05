// Safe: use regular query
const userInput = req.query.username;
db.users.find({ username: userInput });
