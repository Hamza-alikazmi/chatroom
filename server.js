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
const resend = new Resend(process.env.RESEND_API_KEY);

const User = require("./models/User");
const Message = require("./models/Message");

const app = express();
const server = http.createServer(app);
const io = socketio(server);

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

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      let user = await User.findOne({ googleId: profile.id });

      if (!user) {
        // Create new user (requesting access)
        user = await User.create({
          googleId: profile.id,
          username: profile.displayName,
          email: profile.emails[0].value,
          isAllowed: false,
        });

        // Notify admin via Socket
        io.emit("newUserRequest", { username: user.username });

        // Notify admin via email  
        sendAdminEmail(user);
      }

      return done(null, user);
    }
  )
);

// ====== Helper Middleware ======
function checkSecret(req, res, next) {
  if (req.session.secretValidated) return next();
  res.redirect("/");
}

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

// ====== Email Notification (Resend) ======
async function sendAdminEmail(newUser) {
  try {
    await resend.emails.send({
      from: "Chatroom <onboarding@resend.dev>",
      to: process.env.ADMIN_NOTIFY_EMAIL,
      subject: "New Chatroom Access Request",
      html: `<p><strong>${newUser.username}</strong> has requested access to the chatroom.</p>
             <p>Email: ${newUser.email}</p>`
    });

    console.log("Admin notified via email");
  } catch (err) {
    console.error("Email error:", err);
  }
}

// ====== Routes ======
app.get("/", (req, res) => res.render("secret"));

app.post("/validate-secret", (req, res) => {
  const secret = req.body.secret?.trim();
  if (secret === process.env.SECRET_WORD) {
    req.session.secretValidated = true;
    res.redirect("/auth/google");
  } else res.send("<h2>❌ Wrong secret key!</h2>");
});

// Google Auth
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

// Chat page
app.get("/chat", isLoggedIn, async (req, res) => {
  if (!req.user.isAllowed)
    return res.send("<h2>❌ You are not approved by admin yet.</h2>");
  
  const messages = await Message.find().sort({ timestamp: 1 });
  res.render("chat", { username: req.user.username, messages });
});

app.get("/logout", (req, res) => {
  req.logout(() => req.session.destroy(() => res.redirect("/")));
});

// ====== Admin Panel ======
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

// Toggle user approval
app.post("/admin/toggle/:id", isAdmin, async (req, res) => {
  const user = await User.findById(req.params.id);
  if (!user) return res.send("User not found");

  user.isAllowed = !user.isAllowed;
  await user.save();

  res.redirect("/admin");
});

// Delete user
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
