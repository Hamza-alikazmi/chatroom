require("dotenv").config();
const express = require("express");
const http = require("http");
const socketio = require("socket.io");
const mongoose = require("mongoose");
const path = require("path");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const { Resend } = require("resend");

const User = require("./models/User");
const Message = require("./models/Message");

const app = express();
const server = http.createServer(app);
const io = socketio(server);

// ====== Trust Proxy for HTTPS (Koyeb, Heroku, etc.) ======
app.set("trust proxy", 1);

// ====== Middlewares ======
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// ====== Session ======
app.use(
  session({
    secret: process.env.SESSION_SECRET || "supersecret",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: true }, // HTTPS only
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
  })
);

// ====== Passport ======
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});

// ====== Google OAuth ======
const GOOGLE_CALLBACK =
  process.env.GOOGLE_CALLBACK_URL ||
  "https://square.koyeb.app/auth/google/callback";

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: GOOGLE_CALLBACK,
    },
    async (accessToken, refreshToken, profile, done) => {
      let user = await User.findOne({ googleId: profile.id });
      if (!user) {
        user = await User.create({
          googleId: profile.id,
          username: profile.displayName,
          email: profile.emails[0].value,
          isAllowed: false, // admin approval
        });

        // Notify admin via dashboard
        io.emit("newUserRequest", { username: user.username });

        // Notify admin via email
        sendAdminEmail(user);
      }
      done(null, user);
    }
  )
);

// ====== Helper Middlewares ======
function isLoggedIn(req, res, next) {
  if (req.user) return next();
  res.redirect("/");
}

function isAdmin(req, res, next) {
  if (req.session.adminLoggedIn) return next();
  res.redirect("/admin/login");
}

// ====== MongoDB ======
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.log(err));

// ====== Resend Email Notification ======
const resend = new Resend(process.env.RESEND_API_KEY);

async function sendAdminEmail(newUser) {
  try {
    await resend.emails.send({
      from: "Chatroom <onboarding@resend.dev>",
      to: process.env.ADMIN_NOTIFY_EMAIL,
      subject: "New Chatroom Access Request",
      html: `<h2>New User Request</h2>
             <p><strong>${newUser.username}</strong> wants access to chatroom.</p>
             <p>Email: ${newUser.email}</p>`,
    });
    console.log("✔ Admin notified via email");
  } catch (err) {
    console.error("❌ Email error:", err.message);
  }
}

// ====== Routes ======
app.get("/", (req, res) => res.render("secret"));

app.post("/validate-secret", (req, res) => {
  const secret = req.body.secret?.trim();
  if (secret === process.env.SECRET_WORD) {
    req.session.secretValidated = true;
    return res.redirect("/auth/google");
  }
  res.send("<h2>❌ Wrong secret key!</h2>");
});

// Google OAuth
app.get(
  "/auth/google",
  (req, res, next) => {
    if (!req.session.secretValidated) return res.redirect("/");
    next();
  },
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => res.redirect("/chat")
);

// Chat
app.get("/chat", isLoggedIn, async (req, res) => {
  if (!req.user.isAllowed)
    return res.send("<h2>❌ You are not approved yet by admin.</h2>");

  const messages = await Message.find().sort({ timestamp: 1 });
  res.render("chat", { username: req.user.username, messages });
});

app.get("/logout", (req, res) =>
  req.logout(() => req.session.destroy(() => res.redirect("/")))
);
// Privacy Policy page
app.get("/privacy", (req, res) => {
  res.render("privacy"); // render views/privacy.ejs
});

// ====== Admin ======
app.get("/admin/login", (req, res) => res.render("admin-login"));

app.post("/admin/login", (req, res) => {
  const { username, password } = req.body;
  if (
    username === process.env.ADMIN_USERNAME &&
    password === process.env.ADMIN_PASSWORD
  ) {
    req.session.adminLoggedIn = true;
    return res.redirect("/admin");
  }
  res.send("<h2>❌ Invalid credentials</h2>");
});

app.get("/admin", isAdmin, async (req, res) => {
  const users = await User.find();
  res.render("admin", { users });
});

// Approve/unapprove
app.post("/admin/toggle/:id", isAdmin, async (req, res) => {
  const user = await User.findById(req.params.id);
  if (!user) return res.send("User not found");

  user.isAllowed = !user.isAllowed;
  await user.save();

  res.redirect("/admin");
});

// Delete
app.post("/admin/delete/:id", isAdmin, async (req, res) => {
  await User.findByIdAndDelete(req.params.id);
  res.redirect("/admin");
});

// ====== Socket.IO ======
io.on("connection", (socket) => {
  console.log("User connected");

  socket.on("sendMessage", async (data) => {
    const msg = await Message.create({
      username: data.username,
      message: data.message,
    });
    io.emit("newMessage", msg);
  });

  socket.on("disconnect", () => console.log("User disconnected"));
});

// ====== Start Server ======
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
