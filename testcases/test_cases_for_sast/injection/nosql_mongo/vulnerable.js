// JavaScript (Node.js) MongoDB vulnerable example
const userInput = req.query.username;
// DANGEROUS: $where with user input
db.users.find({ $where: `this.username == '${userInput}'` });
