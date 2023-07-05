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
    res.status(403).json({
      message: "Please fill all the fields",
    });
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
        res.status(403).json({ result: "Account already exists" });
      } else {
        await userInfo.save();
        res.json({ result: "Otp has been sent successfully !" });
        // transporter.sendMail(mailData, (error, info) => {
        //   if (error) {
        //     res.status(500).send("Server error");
        //   }
        // });
      }
    } catch (error) {
      console.log(error);
      res.status(500).json({ message: "Server error" });
    }
  }
});

router.post("/verify-otp", async (req, res) => {
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

// Handle password update
router.post("/reset-password", async (req, res) => {
  const otp = Math.floor(Math.random() * 9000 + 1000);
  const mailData = {
    from: process.env.EMAIL,
    to: req.body.email,
    subject: "Verifcation code for password reset",
    text: null,
    html: `<span>Your Verification code is ${otp}</span>`,
  };
  const { email } = req.body;
  if (!email) {
    return res.status(403).json({
      message: "Please fill all the fields",
    });
  }
  try {
    const user = await Users.findOne({ email });
    if (!user) {
      return res.status(403).json({
        message: "User with this email does not exist",
      });
    } else {
      user.otp = otp;
      await user.save();
      res.json({ message: "Otp has been sent successfully !" });
      // transporter.sendMail(mailData, (error, info) => {
      //   if (error) {
      //     res.status(500).send("Server error");
      //   }
      // });
    }
  } catch (error) {
    console.log(error);
    res.status(500).send("Server error");
  }
});

router.put("/verify-reset-otp", async (req, res) => {
  try {
    let salt = await bcrypt.genSalt(saltround);
    let hash_password = await bcrypt.hash(req.body.password, salt);
    let IsValid = await Users.findOne({
      $and: [{ email: req.body.email }, { otp: req.body.otp }],
    });
    if (IsValid) {
      await Users.findOneAndUpdate(
        { email: req.body.email },
        { password: hash_password },
        {
          returnOriginal: false,
        }
      );
      res.status(200).json({ message: "You password have been changed successfully !" });
    } else {
      res.status(401).json({ message: "Wrong Otp !" });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
