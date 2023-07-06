const express = require("express");
const router = new express.Router();
const Users = require("../model/UserSchema");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const authUser = require("../middleware/authUser");
const nodemailer = require("nodemailer");
require("dotenv").config();
const axios = require("axios");
const saltround = 10;
const JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;
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
      transporter.sendMail(mailData, (error, info) => {
        if (error) {
          res.status(500).send("Server error");
        }
      });
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
      res
        .status(200)
        .json({ message: "You password have been changed successfully !" });
    } else {
      res.status(401).json({ message: "Wrong Otp !" });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});

router.get("/fetch-user", authUser, async (req, res) => {
  try {
    const user = await Users.findById(req.id);
    res.status(200).json({ user });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});

router.get("/get-all-users", async (req, res) => {
  try {
    const users = await Users.find({});
    res.status(200).json({ users });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

router.post("/transactions", async (req, res) => {
  try {
    const { transaction, userId } = req.body;
    const user = await Users.findById(userId);
    await user.transactionIds.push(transaction);
    await user.save();
    res.status(201).json({ message: "Transaction ID appended successfully" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});

router.put("/update-transaction", async (req, res) => {
  try {
    const { userId, transactionId, status, transactionType } = req.body;
    const user = await Users.findById(userId);
    const transaction = user.transactionIds.find(
      (transaction) => transaction.id === transactionId
    );

    if (!transaction) {
      return res.status(404).json({ error: "Transaction not found" });
    }

    let updatedUser = null;

    if (transactionType === "deposit" && status === "approved") {
      updatedUser = await Users.findOneAndUpdate(
        {
          _id: userId,
          "transactionIds.id": transactionId,
        },
        {
          $set: {
            "transactionIds.$.status": status,
          },
          $inc: {
            balance: transaction.amount,
          },
        },
        { new: true }
      );
    } else if (transactionType === "withdraw" && status === "approved") {
      if (user.balance < transaction.amount) {
        return res.status(400).json({ error: "Insufficient balance" });
      }

      updatedUser = await Users.findOneAndUpdate(
        {
          _id: userId,
          "transactionIds.id": transactionId,
        },
        {
          $set: {
            "transactionIds.$.status": status,
          },
          $inc: {
            balance: -transaction.amount,
          },
        },
        { new: true }
      );
    } else {
      return res.status(400).json({ error: "Invalid transaction type or status" });
    }

    if (!updatedUser) {
      return res.status(404).json({ error: "User not found" });
    }

    res.status(200).json({ message: "Transaction status updated successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});



// Route to fetch transactionIds for all users (admin-only access)
router.get("/transactionIds", async (req, res) => {
  try {
    const pipeline = [
      {
        $match: {
          role: { $ne: "admin" }, // Exclude admin user
        },
      },
      {
        $unwind: "$transactionIds",
      },
      {
        $group: {
          _id: null,
          transactionIds: { $push: "$transactionIds" },
        },
      },
      {
        $project: {
          _id: 0,
          transactionIds: 1,
        },
      },
    ];
    const results = await Users.aggregate(pipeline);
    if (results.length === 0) {
      return res.json({ transactionIds: [] });
    }
    const transactionIds = results[0].transactionIds;
    res.json({ transactionIds });
  } catch (error) {
    console.error("Error fetching transactionIds:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.get("/depositlist/:id", async (req, res) => {
  try {
    const { data } = await axios.get("https://exolix.com/api/v2/transactions", {
      headers: {
        Authorization:
          "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InNnbmFncHVyZThAZ21haWwuY29tIiwic3ViIjoyNzQxOSwiaWF0IjoxNjg4MTA5NjQ4LCJleHAiOjE4NDU4OTc2NDh9.dXVHXGfNWb1BU55JVRk9MA0Y1xlnkYazXYxREK1dy4Y",
      },
    });
    const { transactions } = data.data;
    res.status(200).json({ data });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});
module.exports = router;
