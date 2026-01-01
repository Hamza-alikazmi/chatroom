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
  (req, res) => {
    const token = jwt.sign(
      {
        id: req.user._id,
        username: req.user.username,
        isAllowed: req.user.isAllowed,
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.redirect(`myapp://login?token=${token}`);
  }
);

// ====== USER API ======
app.get("/me", jwtAuth, async (req, res) => {
  const user = await User.findById(req.user.id);
  res.json(user);
});

// ====== CHAT API ======
app.get("/chat/messages", jwtAuth, async (req, res) => {
  if (!req.user.isAllowed)
    return res.status(403).json({ error: "Not approved" });

  const messages = await Message.find().sort({ timestamp: 1 });
  res.json(messages);
});

// ====== ADMIN (JWT BASED) ======
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
io.use((socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    socket.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    next(new Error("Unauthorized"));
  }
});

io.on("connection", (socket) => {
  socket.on("sendMessage", async (data) => {
    if (!socket.user.isAllowed) return;

    const msg = await Message.create({
      ...data,
      user: socket.user.id,
      timestamp: new Date(),
    });

    io.emit("newMessage", msg);
  });
});

// ====== START ======
const PORT = process.env.PORT || 3000;
server.listen(PORT, () =>
  console.log(`API running on port ${PORT}`)
);
