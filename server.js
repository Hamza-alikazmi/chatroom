require("dotenv").config();
const express = require("express");
const http = require("http");
const socketio = require("socket.io");
const mongoose = require("mongoose");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { Resend } = require("resend");

const admin = require("./firebase");
const User = require("./models/User");
const Message = require("./models/Message");

const app = express();
const server = http.createServer(app);

const io = socketio(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
});

// ====== Middlewares ======
app.use(cors({ origin: true }));
app.use(express.json());

// ====== MongoDB ======
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch(console.error);

// ====== Passport ======
app.use(passport.initialize());

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      let user = await User.findOne({ googleId: profile.id });

      if (!user) {
        user = await User.create({
          googleId: profile.id,
          username: profile.displayName,
          email: profile.emails[0].value,
          isAllowed: false,
        });

        io.emit("newUserRequest", { username: user.username });
        sendAdminEmail(user);
      }

      done(null, user);
    }
  )
);

// ====== JWT Middleware ======
function jwtAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "No token" });

  try {
    const token = auth.split(" ")[1];
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

// ====== Resend ======
const resend = new Resend(process.env.RESEND_API_KEY);

async function sendAdminEmail(user) {
  await resend.emails.send({
    from: "Chatroom <onboarding@resend.dev>",
    to: process.env.ADMIN_NOTIFY_EMAIL,
    subject: "New Chatroom Access Request",
    html: `<p>${user.username} (${user.email}) requested access.</p>`,
  });
}

// ====== AUTH ROUTES ======
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { session: false }),
  async (req, res) => {
    const user = await User.findById(req.user._id); // Always fetch fresh user

    const token = jwt.sign(
      {
        id: user._id,
        username: user.username,
        isAllowed: user.isAllowed,
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    // Single HTML page, no duplicate res.send
    res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>Login Successful</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { font-family: sans-serif; text-align: center; padding: 50px; background: #f0f0f0; }
    .container { max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
    .spinner { border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 20px auto; }
    @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
  </style>
</head>
<body>
  <div class="container">
    <h2>✅ Login Successful!</h2>
    <p>Returning to ChatApp...</p>
    <div class="spinner"></div>
    <p><small>If not redirected automatically, <a href="myapp://login?token=${token}">click here</a> or close this tab.</small></p>
  </div>
  <script>
    window.location.href = "myapp://login?token=${token}";
  </script>
</body>
</html>
    `);
  }
);

// ====== USER API ======
app.get("/me", jwtAuth, async (req, res) => {
  const user = await User.findById(req.user.id); // Always fresh
  res.json(user);
});

// ====== CHAT API ======
app.get("/chat/messages", jwtAuth, async (req, res) => {
  const user = await User.findById(req.user.id); // Fresh DB check
  if (!user.isAllowed)
    return res.status(403).json({ error: "Not approved" });

  const messages = await Message.find().sort({ timestamp: 1 });
  res.json(messages);
});

// ====== ADMIN ======
app.post("/admin/login", (req, res) => {
  const { username, password } = req.body;

  if (
    username === process.env.ADMIN_USERNAME &&
    password === process.env.ADMIN_PASSWORD
  ) {
    const token = jwt.sign(
      { admin: true },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );
    return res.json({ token });
  }

  res.status(401).json({ error: "Invalid credentials" });
});

function adminAuth(req, res, next) {
  try {
    const token = req.headers.authorization.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded.admin) throw Error();
    next();
  } catch {
    res.status(403).json({ error: "Forbidden" });
  }
}

app.get("/admin/users", adminAuth, async (req, res) => {
  const users = await User.find();
  res.json(users);
});

app.post("/admin/toggle/:id", adminAuth, async (req, res) => {
  const user = await User.findById(req.params.id);
  user.isAllowed = !user.isAllowed;
  await user.save();
  res.json({ success: true });
});

app.post("/admin/delete/:id", adminAuth, async (req, res) => {
  await User.findByIdAndDelete(req.params.id);
  res.json({ success: true });
});

// ====== SOCKET.IO JWT AUTH ======
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    const payload = jwt.verify(token, process.env.JWT_SECRET);

    // Fetch fresh user from DB
    const user = await User.findById(payload.id);
    if (!user || !user.isAllowed) return next(new Error("Unauthorized"));

    socket.user = user; // Overwrite with DB data
    next();
  } catch {
    next(new Error("Unauthorized"));
  }
});

io.on("connection", (socket) => {
  console.log(`User connected: ${socket.user.username}`);

  socket.on("sendMessage", async (data) => {
    try {
      if (!data.text || !data.text.trim()) return;

      const msg = await Message.create({
        username: socket.user.username,
        message: data.text.trim(),
        timestamp: new Date(),
      });

      io.emit("newMessage", {
        username: msg.username,
        message: msg.message,
        time: msg.timestamp,
      });

      const users = await User.find({
        isAllowed: true,
        fcmToken: { $exists: true, $ne: null },
        _id: { $ne: socket.user._id },
      });

      await Promise.all(
        users.map((user) =>
          admin
            .messaging()
            .send({
              token: user.fcmToken,
              notification: {
                title: "Square",
                body: "You have one new notification from your College",
              },
              android: { priority: "high" },
              data: { type: "chat" },
            })
            .catch((err) => console.error("FCM error:", err))
        )
      );
    } catch (err) {
      console.error("Error in sendMessage:", err);
      socket.emit("error", { message: "Message could not be sent" });
    }
  });

  socket.on("disconnect", () => {
    console.log(`User disconnected: ${socket.user.username}`);
  });
});

// ====== FCM TOKEN ======
app.post("/fcm/token", jwtAuth, async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: "No token" });

  await User.findByIdAndUpdate(req.user.id, { fcmToken: token });
  res.json({ success: true });
});

// ====== START SERVER ======
const PORT = process.env.PORT || 3000;
server.listen(PORT, () =>
  console.log(`API running on port ${PORT}`)
);

