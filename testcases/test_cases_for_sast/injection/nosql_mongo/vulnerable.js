// JavaScript vulnerable
const userInput = req.query.username;
db.users.find({ $where: `this.username == '${userInput}'` });  // DANGEROUS
