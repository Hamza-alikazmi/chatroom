const jwt = require("jsonwebtoken");
const User = require("../models/User");

module.exports = async function authJWT(req, res, next) {
  const header = req.headers.authorization;

  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "No token" });
  }

  const token = header.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(401).json({ error: "User not found" });
    }

    req.user = user; // 🔥 THIS IS THE KEY
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
};
