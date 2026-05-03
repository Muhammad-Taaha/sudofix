// Safe: use regular query object
const userInput = req.query.username;
db.users.find({ username: userInput });
