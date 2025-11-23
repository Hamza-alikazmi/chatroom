const express = require("express");
const http = require("http");
const socketio = require("socket.io");
const mongoose = require("mongoose");
const Message = require("./models/Message");
const path = require("path");
const cors = require("cors");
require('dotenv').config();


const app = express();
const server = http.createServer(app);
const io = socketio(server);

app.use(cors());
app.use(express.static(path.join(__dirname, "public")));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log("MongoDB connected"))
.catch(err => console.log(err));

// Routes
app.get("/", (req, res) => {
    res.render("index");
});

app.get("/chat", async (req, res) => {
    const username = req.query.username;
    const secret = req.query.secret;

    // Check username and secret
    if (!username) return res.redirect("/");
    if (secret !== process.env.SECRET_WORD) {
        return res.send("<h2>❌ Wrong secret word! You cannot join the chat.</h2>");
    }

    const messages = await Message.find().sort({ time: 1 });
    res.render("chat", { username, messages });
});


// Socket.IO
io.on("connection", (socket) => {
    console.log("New user connected");

    socket.on("sendMessage", async (data) => {
        const msg = await Message.create({
            username: data.username,
            message: data.message
        });
        io.emit("newMessage", msg);
    });

    socket.on("disconnect", () => {
        console.log("User disconnected");
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));

