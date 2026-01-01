// server.js (Backend API – JSON only)
require("dotenv").config();
const express = require("express");
const http = require("http");
const socketio = require("socket.io");
const mongoose = require("mongoose");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const cors = require("cors");
const { Resend } = require("resend");

const User = require("./models/User");
const Message = require("./models/Message");

const app = express();
const server = http.createServer(app);
const io = socketio(server, {
  cors: {
    origin: true,
    credentials: true,
    methods: ["GET", "POST"],
  },
});

// ================== MIDDLEWARES ==================
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set("trust proxy", 1);

// ================== SESSION ==================
app.use(
  session({
    name: "chatroom.sid",
    secret: process.env.SESSION_SECRET || "supersecret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: true,
      sameSite: "none",
    },
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
  })
);

// ================== PASSPORT ==================
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// ================== GOOGLE OAUTH ==================
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ googleId: profile.id });

        if (!user) {
          user = await User.create({
            googleId: profile.id,
            username: profile.displayName,
            email: profile.emails?.[0]?.value,
            isAllowed: false,
          });

          io.emit("newUserRequest", { username: user.username });
          sendAdminEmail(user).catch(console.error);
        }

        done(null, user);
      } catch (err) {
        done(err);
      }
    }
  )
);

// ================== DATABASE ==================
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch(console.error);

// ================== EMAIL (RESEND) ==================
const resend = new Resend(process.env.RESEND_API_KEY);

async function sendAdminEmail(user) {
  await resend.emails.send({
    from: "Chatroom <onboarding@resend.dev>",
    to: process.env.ADMIN_NOTIFY_EMAIL,
    subject: "New Chatroom Access Request",
    html: `<p><strong>${user.username}</strong> (${user.email}) requested access.</p>`,
  });
}

async function sendChatroomEmails({ sender, message }) {
  const users = await User.find({
    isAllowed: true,
    email: { $exists: true, $ne: null },
    username: { $ne: sender },
  }).select("email");

  if (!users.length) return;

  await resend.emails.send({
    from: "Chatroom <notifications@resend.dev>",
    to: users.map((u) => u.email),
    subject: `You have new message...`,
    html: `<p> One of your classmate have sent you a new message:</p>
    `,
  });
}

// ================== AUTH ROUTES ==================
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/auth/fail" }),
  (req, res) => {
    res.json({
      success: true,
      user: {
        id: req.user._id,
        username: req.user.username,
        isAllowed: req.user.isAllowed,
      },
    });
  }
);

app.get("/auth/fail", (req, res) =>
  res.status(401).json({ success: false })
);

app.get("/logout", (req, res) => {
  req.logout(() =>
    req.session.destroy(() => res.json({ success: true }))
  );
});

// ================== USER API ==================
app.get("/me", (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Unauthorized" });
  res.json(req.user);
});

// ================== CHAT API ==================
app.get("/chat/messages", async (req, res) => {
  if (!req.user || !req.user.isAllowed)
    return res.status(403).json({ error: "Not approved" });

  const messages = await Message.find().sort({ timestamp: 1 });
  res.json(messages);
});

// ================== ADMIN API ==================
app.post("/admin/login", (req, res) => {
  const { username, password } = req.body;

  if (
    username === process.env.ADMIN_USERNAME &&
    password === process.env.ADMIN_PASSWORD
  ) {
    req.session.adminLoggedIn = true;
    return res.json({ success: true });
  }

  res.status(401).json({ success: false });
});

app.get("/admin", async (req, res) => {
  if (!req.session.adminLoggedIn)
    return res.status(403).json({ error: "Forbidden" });

  const users = await User.find();
  res.json(users);
});

app.post("/admin/toggle/:id", async (req, res) => {
  if (!req.session.adminLoggedIn)
    return res.status(403).json({ error: "Forbidden" });

  const user = await User.findById(req.params.id);
  user.isAllowed = !user.isAllowed;
  await user.save();

  res.json({ success: true });
});

app.post("/admin/delete/:id", async (req, res) => {
  if (!req.session.adminLoggedIn)
    return res.status(403).json({ error: "Forbidden" });

  await User.findByIdAndDelete(req.params.id);
  res.json({ success: true });
});

// ================== SOCKET.IO ==================
io.on("connection", (socket) => {
  console.log("🟢 Socket connected:", socket.id);

  socket.on("sendMessage", async (data) => {
    try {
      const msg = await Message.create({
        username: data.username,
        message: data.message,
        timestamp: data.timestamp || Date.now(),
      });

      io.emit("newMessage", msg);

      // Email notifications (non-blocking)
      sendChatroomEmails({
        sender: msg.username,
        message: msg.message,
      }).catch(console.error);
    } catch (err) {
      console.error("Message error:", err);
    }
  });

  socket.on("disconnect", () => {
    console.log("🔴 Socket disconnected:", socket.id);
  });
});

// ================== START SERVER ==================
const PORT = process.env.PORT || 3000;
server.listen(PORT, () =>
  console.log(`🚀 API running on port ${PORT}`)
);
