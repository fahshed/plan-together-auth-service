const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const router = express.Router();
require("dotenv").config();

const db = require("../config/firebase");
const usersRef = db.collection("users");

function generateToken(userId) {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: "1d" });
}

// @route   GET /users/ (test route)
router.get("/", (req, res) => {
  res.send("Auth service is running");
});

// @route   POST /users/signup
router.post("/signup", async (req, res) => {
  const { firstName, lastName, email, password } = req.body;

  try {
    const existingUser = await usersRef.where("email", "==", email).get();

    if (!existingUser.empty) {
      return res.status(400).json({ error: "Email already in use" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUserRef = usersRef.doc();
    const userData = {
      id: newUserRef.id,
      firstName,
      lastName,
      email,
      password: hashedPassword,
      createdAt: new Date(),
    };

    await newUserRef.set(userData);

    const token = generateToken(newUserRef.id);

    res.status(201).json({
      token,
      user: {
        id: newUserRef.id,
        firstName,
        lastName,
        email,
      },
    });
  } catch (err) {
    res.status(500).json({ error: "Signup failed", details: err.message });
  }
});

// @route   POST /users/login
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const snapshot = await usersRef.where("email", "==", email).get();

    if (snapshot.empty) {
      return res.status(404).json({ error: "User not found" });
    }

    const userDoc = snapshot.docs[0];
    const user = userDoc.data();

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = generateToken(user.id);

    res.json({
      token,
      user: {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
      },
    });
  } catch (err) {
    res.status(500).json({ error: "Login failed", details: err.message });
  }
});

// @route   GET /users/me
router.get("/me", async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing or invalid token" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userDoc = await usersRef.doc(decoded.userId).get();

    if (!userDoc.exists) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = userDoc.data();

    res.json({
      id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
    });
  } catch (err) {
    res.status(401).json({ error: "Invalid token", details: err.message });
  }
});

// @route   POST /users/email
router.post("/email", async (req, res) => {
  const { email } = req.body;

  try {
    const snapshot = await usersRef.where("email", "==", email).get();

    if (snapshot.empty) {
      return res.status(404).json({ error: "User not found" });
    }

    const userDoc = snapshot.docs[0];
    const user = userDoc.data();

    res.json({
      id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
    });
  } catch (err) {
    res
      .status(500)
      .json({ error: "Failed to retrieve user", details: err.message });
  }
});

module.exports = router;
