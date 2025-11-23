const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
    googleId: String,
    username: String,
    email: String,
    isAdmin: { type: Boolean, default: false },
    isAllowed: { type: Boolean, default: false } // admin approves
});

module.exports = mongoose.model("User", userSchema);
