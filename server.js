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
const jwt = require("jsonwebtoken");
const authJWT = require("./middlewares/auth");

const User = require("./models/User");
const Message = require("./models/Message");

const app = express();
const server = http.createServer(app);

// ====== Socket.IO with JWT Middleware ======
const io = socketio(server, {
  cors: { 
    origin: ["http://localhost", "capacitor://localhost", "https://square.koyeb.app"], 
    methods: ["GET", "POST"],
    credentials: true 
  },
});

io.use(async (socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error("Authentication error: No token provided"));

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user || !user.isAllowed) {
      return next(new Error("Access denied: Not approved by admin"));
    }
    socket.user = user;
    next();
  } catch (err) {
    next(new Error("Authentication error: Invalid token"));
  }
});

// ====== Middlewares ======
app.use(cors({ 
  origin: ["http://localhost", "capacitor://localhost", "https://square.koyeb.app"], 
  credentials: true 
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set("trust proxy", 1);

// ====== Session (Admin Web Panel) ======
app.use(
  session({
    name: "chatroom.sid",
    secret: process.env.SESSION_SECRET || "supersecret",
    resave: false,
    saveUninitialized: false,
    cookie: { 
      secure: process.env.NODE_ENV === "production", 
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      maxAge: 1000 * 60 * 60 * 24 // 24 hours
    },
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
  })
);

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

// ====== Google OAuth ======
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
            email: profile.emails[0].value,
            isAllowed: false,
          });
          io.emit("newUserRequest", { username: user.username });
          sendAdminEmail(user);
        }
        done(null, user);
      } catch (err) {
        done(err, null);
      }
    }
  )
);

// ====== MongoDB ======
mongoose.connect(process.env.MONGO_URI, { 
  useNewUrlParser: true, 
  useUnifiedTopology: true 
})
.then(() => console.log("MongoDB connected"))
.catch(console.error);

// ====== Resend Notification ======
const resend = new Resend(process.env.RESEND_API_KEY);
async function sendAdminEmail(user) {
  try {
    await resend.emails.send({
      from: "Chatroom <onboarding@resend.dev>",
      to: process.env.ADMIN_NOTIFY_EMAIL,
      subject: "New Access Request",
      html: `<p><strong>${user.username}</strong> (${user.email}) requested access.</p>`,
    });
  } catch (e) { console.error("Email failed", e); }
}

// ====== Routes ======
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get("/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/auth/fail" }),
  (req, res) => {
    const token = jwt.sign(
      { id: req.user._id, username: req.user.username },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );
    res.redirect(`myapp://login?token=${token}`);
  }
);

app.get("/me", authJWT, (req, res) => {
  res.json({
    id: req.user._id,
    username: req.user.username,
    email: req.user.email,
    isAllowed: req.user.isAllowed,
  });
});

app.get("/chat/messages", authJWT, async (req, res) => {
  if (!req.user.isAllowed) return res.status(403).json({ error: "Not approved" });
  try {
    const messages = await Message.find().sort({ timestamp: 1 }).limit(100);
    res.json(messages);
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// ====== Admin APIs ======
app.post("/admin/login", (req, res) => {
  const { username, password } = req.body;
  if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
    req.session.adminLoggedIn = true;
    return res.json({ success: true });
  }
  res.status(401).json({ success: false });
});

const isAdmin = (req, res, next) => {
  if (req.session.adminLoggedIn) return next();
  res.status(403).json({ error: "Forbidden" });
};

app.get("/admin", isAdmin, async (req, res) => {
  try {
    const users = await User.find();
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/admin/toggle/:id", isAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ error: "User not found" });
    user.isAllowed = !user.isAllowed;
    await user.save();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// ====== Socket Events ======
io.on("connection", (socket) => {
  console.log(`User connected: ${socket.user.username}`);

  socket.on("sendMessage", async (data) => {
    try {
      const msg = await Message.create({
        username: socket.user.username,
        message: data.message,
        timestamp: new Date()
      });
      io.emit("newMessage", msg);
    } catch (err) {
      console.error("Failed to save message", err);
    }
  });

  socket.on("typing", () => {
    socket.broadcast.emit("typing", socket.user.username);
  });

  socket.on("disconnect", () => {
    console.log(`User disconnected: ${socket.user.username}`);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`API running on ${PORT}`));
