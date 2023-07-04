require("dotenv").config();
const JWT_SECRET = process.env.JWT_SECRET;
const jwt = require("jsonwebtoken");

const authUser = (req, res, next) => {
  //  get the user from the jwt and add id to req object
  const token = req.headers["auth-token"];
  try {
    if (!token) {
      res.status(401).send("Access denied");
    }
    const data = jwt.verify(token, JWT_SECRET);
    req.id = data.id;
    next();
  } catch (error) {
    res.status(401).send(error);
  }
};

module.exports = authUser;
