import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import fetch from "node-fetch";

dotenv.config();

const app = express();
app.use(express.json());

// CORS
app.use(
  cors({
    origin: process.env.FRONTEND_ORIGINS.split(","),
    credentials: true,
  })
);

// EXPRESS SESSION (needed for Google OAuth)
app.use(
  session({
    secret: process.env.SESSION_SECRET || "moneyflow_session",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

// ------------------------------
// MONGO CONNECTION
// ------------------------------
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected ✔"))
  .catch((err) => console.log("MongoDB Error:", err));

// ------------------------------
// MODELS
// ------------------------------
const User = mongoose.model(
  "User",
  new mongoose.Schema({
    email: { type: String, unique: true },
    password: String,
    username: { type: String, default: "" },
    base_currency: { type: String, default: "INR" },
  })
);

const Expense = mongoose.model(
  "Expense",
  new mongoose.Schema({
    userId: String,
    amount: Number,
    category: String,
    note: String,
    currency: { type: String, default: "INR" },
    date: { type: Date, default: Date.now },
  })
);

// ------------------------------
// GOOGLE STRATEGY
// ------------------------------
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ email: profile.emails[0].value });

        if (!user) {
          user = await User.create({
            email: profile.emails[0].value,
            username: "",
            password: "",
          });
        }

        return done(null, user);
      } catch (err) {
        return done(err, null);
      }
    }
  )
);

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});

// ------------------------------
// GOOGLE ROUTES (fixed)
// ------------------------------
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: process.env.FRONTEND_URL }),
  (req, res) => {
    // Sign JWT for the logged-in user
    const token = jwt.sign({ id: req.user._id }, JWT_SECRET, {
      expiresIn: "7d",
    });

    // Choose a display name to send back to frontend:
    // Prefer stored username (if the user previously set it),
    // otherwise fall back to the Google profile displayName saved in the DB (if any),
    // otherwise empty string.
    const displayName = req.user.username && req.user.username.trim() !== ""
      ? req.user.username
      : (req.user.name && req.user.name.trim() !== "" ? req.user.name : "");

    // Build redirect URL with 'name' param (frontend reads params.get("name"))
    const redirectURL = `${process.env.FRONTEND_URL}/google-callback` +
      `?token=${encodeURIComponent(token)}` +
      `&email=${encodeURIComponent(req.user.email || "")}` +
      `&name=${encodeURIComponent(displayName)}` +
      `&userId=${encodeURIComponent(req.user._id.toString())}`;

    return res.redirect(redirectURL);
  }
);

// ------------------------------
// AUTH MIDDLEWARE
// ------------------------------
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) return res.status(401).json({ msg: "No token" });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ msg: "Invalid token" });

    req.user = decoded;
    next();
  });
};

// ------------------------------
// REGISTER
// ------------------------------
app.post("/api/register", async (req, res) => {
  const { email, password, username } = req.body;

  try {
    const hashed = await bcrypt.hash(password, 10);

    await User.create({
      email,
      password: hashed,
      username: username || "",
    });

    res.json({ msg: "Registered successfully" });
  } catch (e) {
    res.status(400).json({ msg: "Email already exists" });
  }
});

// ------------------------------
// LOGIN
// ------------------------------
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ msg: "Invalid email or password" });

  if (!user.password)
    return res.status(400).json({ msg: "Use Google login for this account" });

  const match = await bcrypt.compare(password, user.password);
  if (!match)
    return res.status(400).json({ msg: "Invalid email or password" });

  const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });

  res.json({
    token,
    user: {
      id: user._id,
      email: user.email,
      username: user.username,
      base_currency: user.base_currency,
    },
  });
});

// ------------------------------
// UPDATE USERNAME
// ------------------------------
app.post("/api/set-username", authenticate, async (req, res) => {
  const { username } = req.body;

  if (!username || username.trim().length < 3) {
    return res.status(400).json({ msg: "Invalid username" });
  }

  const user = await User.findByIdAndUpdate(
    req.user.id,
    { username },
    { new: true }
  );

  res.json({
    msg: "Username updated",
    user: {
      id: user._id,
      email: user.email,
      username: user.username,
      base_currency: user.base_currency,
    },
  });
});

// ------------------------------
// EXPENSE CRUD
// ------------------------------
app.get("/api/expenses", authenticate, async (req, res) => {
  const data = await Expense.find({ userId: req.user.id }).sort({ date: -1 });
  res.json(data);
});

app.post("/api/expenses", authenticate, async (req, res) => {
  const newExpense = await Expense.create({
    ...req.body,
    userId: req.user.id,
  });
  res.json(newExpense);
});

app.delete("/api/expenses/:id", authenticate, async (req, res) => {
  await Expense.deleteOne({ _id: req.params.id, userId: req.user.id });
  res.json({ msg: "Deleted" });
});

// ------------------------------
// CURRENCY API
// ------------------------------
app.get("/api/currency", async (req, res) => {
  try {
    const r = await fetch("https://api.frankfurter.dev/v1/latest?from=INR");
    const data = await r.json();
    res.json(data);
  } catch {
    res.json({ rates: {} });
  }
});

// ------------------------------
app.get("/", (req, res) => res.send("Backend OK ✔"));

// ------------------------------
app.listen(PORT, () =>
  console.log(`Backend running on http://localhost:${PORT}`)
);
