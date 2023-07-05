const express = require("express");
const router = new express.Router();
const Users = require("../model/UserSchema");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const authUser = require("../middleware/authUser");
const nodemailer = require("nodemailer");
require("dotenv").config();
const saltround = 10;
const authRole = require("../middleware/authRole");
const JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;
// const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
const transporter = nodemailer.createTransport({
  port: 465,
  host: "smtp.gmail.com",
  auth: {
    user: process.env.EMAIL,
    pass: process.env.PASSWORD,
  },
  secure: true, // upgrades later with STARTTLS -- change this based on the PORT
});

router.post("/", async (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password || !name) {
    res.status(403).send("Please fill all the data");
  } else {
    console.log(email, password, name);
    try {
      const otp = Math.floor(Math.random() * 9000 + 1000);
      let salt = await bcrypt.genSalt(saltround);
      let hash_password = await bcrypt.hash(password, salt);
      let user = {
        name,
        email,
        password: hash_password,
        otp,
      };
      const mailData = {
        from: process.env.EMAIL,
        to: req.body.email,
        subject: "Verifcation code",
        text: null,
        html: `<span>Your Verification code is ${otp}</span>`,
      };
      let userInfo = new Users(user);
      let IsEmail = await Users.findOne({ email: req.body.email });
      if (IsEmail) {
        res.status(401).json({ result: "User Already Exists!" });
      } else {
        await userInfo.save();
        res.json({ result: "Otp has been sent successfully !" });
        transporter.sendMail(mailData, (error, info) => {
          if (error) {
            res.status(500).send("Server error");
          }
        });
      }
    } catch (error) {
      console.log(error);
      res.status(500).json({ message: "Server error" });
    }
  }
});

router.post("/verify", async (req, res) => {
  try {
    let IsValid = await Users.findOne({
      $and: [{ email: req.body.email }, { otp: req.body.otp }],
    });
    if (IsValid) {
      await Users.findOneAndUpdate(
        { email: req.body.email },
        { isVerified: true },
        {
          returnOriginal: false,
        }
      );
      res.status(200).json({ message: "You are now successfully verified" });
    } else {
      res.status(401).json({ message: "Wrong Otp !" });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});

router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      res.status(403).send("please fill the data");
    }
    let IsValidme = await Users.findOne({ email: email });
    if (!IsValidme) {
      res.status(403).json({ message: "Invalid credential" });
    } else {
      if (IsValidme.isVerified) {
        let data = {
          id: IsValidme.id,
          name: IsValidme.name,
        };
        let isMatch = await bcrypt.compare(password, IsValidme.password);
        if (isMatch) {
          let authToken = jwt.sign({ data }, JWT_ACCESS_SECRET, {
            expiresIn: "10day",
          });
          res.status(200).json({ authToken });
        } else {
          res.status(403).json({ message: "Invalid credential" });
        }
      } else {
        res.status(401).json({
          message: "Please verify your email address",
        });
      }
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});

// Step 1: Request password reset
router.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(403).send("Please provide an email address");
  }

  try {
    const user = await Users.findOne({ email });
    if (!user) {
      return res.status(401).send("User not found");
    }

    // Generate a random token for password reset
    const resetToken = crypto.randomBytes(20).toString("hex");
    user.resetToken = resetToken;
    user.resetTokenExpiration = Date.now() + 3600000; // Token expires in 1 hour
    await user.save();

    const resetLink = `${process.env.SERVER_URL}/reset-password?token=${resetToken}`;
    console.log(resetLink);
    const mailData = {
      from: process.env.EMAIL,
      to: email,
      subject: "Password Reset",
      text: `You are receiving this email because you have requested to reset your password. Please click on the following link to reset your password:\n\n${resetLink}`,
    };
    transporter.sendMail(mailData, (error, info) => {
      if (error) {
        console.log(error);
        res.status(500).send("Server error");
      } else {
        res.status(200).send("Password reset link sent to your email");
      }
    });
  } catch (error) {
    console.log(error);
    res.status(500).send("Server error");
  }
});

// Step 2: Handle password reset link
router.get("/reset-password", async (req, res) => {
  const { token } = req.query;
  console.log(req.query);
  if (!token) {
    console.log("No token", token);
    return res.status(400).send("Invalid token");
  }

  try {
    const user = await Users.findOne({
      resetToken: token,
      resetTokenExpiration: { $gt: Date.now() },
    });
    if (!user) {
      return res.status(400).send("Invalid or expired reset token");
    }
    res.status(200).json({
      message: "Password reset link is valid",
    });
  } catch (error) {
    console.log(error);
    res.status(500).send("Server error");
  }
});

// Step 3: Handle password update
router.put("/reset-password", async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) {
    return res.status(400).send("Invalid request");
  }

  try {
    const user = await Users.findOne({
      resetToken: token,
      resetTokenExpiration: { $gt: Date.now() },
    });
    if (!user) {
      return res.status(400).send("Invalid or expired reset token");
    }
    // Hash the new password
    const salt = await bcrypt.genSalt(saltround);
    const hashPassword = await bcrypt.hash(password, salt);
    user.password = hashPassword;
    user.resetToken = undefined;
    user.resetTokenExpiration = undefined;
    await user.save();
    res.status(200).json({
      message: "Password updated successfully",
    });
  } catch (error) {
    console.log(error);
    res.status(500).send("Server error");
  }
});


module.exports = router;
