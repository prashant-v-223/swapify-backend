const express = require("express");
const router = new express.Router();
const Users = require("../model/UserSchema");
const bcrypt = require("bcrypt");
const JWT_SECRET =  process.env.JWT_SECRET;;
const jwt = require("jsonwebtoken");
const authUser = require("../middleware/authUser");
const nodemailer = require("nodemailer");
require("dotenv").config();
const saltround = 10;
const transporter = nodemailer.createTransport({
  port: 465,
  host: "smtp.gmail.com",
  auth: {
    user: process.env.EMAIL,
    pass:  process.env.PASSWORD,
  },
  secure: true, // upgrades later with STARTTLS -- change this based on the PORT
});

router.post("/", async (req, res) => {
  const random = Math.floor(Math.random() * 9000 + 1000);
  let salt = await bcrypt.genSalt(saltround);
  let hash_password = await bcrypt.hash(req.body.password, salt);
  let user = {
    name: req.body.name,
    email: req.body.email,
    password: hash_password,
    otp: random,
  };
  const mailData = {
    from: process.env.EMAIL,
    to: req.body.email,
    subject: "Verifcation code",
    text: null,
    html: `<span>Your Verification code is ${random}</span>`,
  };
  let userInfo = new Users(user);
  let IsEmail = await Users.findOne({ email: req.body.email });
  try {
    if (IsEmail) {
      res.status(401).send("User Already Exists!");
    } else {
      await userInfo.save();
      res.json({ result: "success" });
      transporter.sendMail(mailData, (error, info) => {
        if (error) {
          res.status(500).send("Server error");
        }
      });
    }
  } catch (error) {
    res.status(500).send("Server error");
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
      res.status(200).send("Verified");
    } else {
      res.status(401).send("wrong otp");
    }
  } catch (error) {
    console.log(error);
    res.status(500).send("Server error");
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
      res.status(403).send("Invalid credential");
    } else {
      if (IsValidme.isVerified) {
        let data = {
          id: IsValidme.id,
          name: IsValidme.name
        };
        let isMatch = await bcrypt.compare(password, IsValidme.password);
        if (isMatch) {
          let authToken = jwt.sign(data, JWT_SECRET);
          res.status(200).send({ authToken });
        } else {
          res.status(403).send("Invalid credential");
        }
      } else {
        res.status(401).send("Your account is not verified");
      }
    }
  } catch (error) {
    res.status(500).send(error);
  }
});

router.get("/getuser", authUser, async (req, res) => {
  try {
    const userid = req.id;
    const user = await Users.findById(userid);
    res.status(200).send(user);
  } catch (error) {
    console.log(error);
    res.status(401).send("Server error");
  }
});

module.exports = router;
