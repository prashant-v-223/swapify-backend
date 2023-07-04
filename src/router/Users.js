const express = require("express");
const router = new express.Router();
const Users = require("../model/UserSchema");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const authUser = require("../middleware/authUser");
const nodemailer = require("nodemailer");
require("dotenv").config();
const saltround = 10;
const authRole = require("../middleware/authRole");
const RefreshToken = require("../model/RefreshToken");
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
      console.log(error);
      res.status(500).send("Server error");
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
      res.status(200).send("You are now successfully verified");
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
          name: IsValidme.name,
        };
        let isMatch = await bcrypt.compare(password, IsValidme.password);
        if (isMatch) {
          let authToken = jwt.sign({ data }, JWT_ACCESS_SECRET, {
            expiresIn: "30m",
          });
          // let refreshToken = jwt.sign({ data }, JWT_REFRESH_SECRET, {
          //   expiresIn: "30d",
          // });
          // let save_Refresh_Token = new RefreshToken({ token:refreshToken });
            // await save_Refresh_Token.save();
          res.status(200).send({ authToken });
        } else {
          res.status(403).send("Invalid credential");
        }
      } else {
        res.status(401).send("Your account is not verified");
      }
    }
  } catch (error) {
    console.log(error);
    res.status(500).send(error);
  }
});

// router.post("/refresh", async (req, res) => {
//   try {
//     const { refreshToken } = req.body;
//     if (!refreshToken) {
//       res.status(403).send("Please fill the inputs");
//     }
//     const token = await RefreshToken.findOne({ token:refreshToken });
//     if (!token) {
//       res.status(403).send("Invalid token");
//     } else {
//       let data = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
//       let authToken = jwt.sign({ data }, JWT_ACCESS_SECRET, {
//         expiresIn: "1h",
//       });
//       res.status(200).send({ authToken });
//     }
//   } catch (error) {
//     console.log(error);
//   }
// });

router.post("/reset-password", async (req, res) => {
  const { email, password, newPassword } = req.body;
  if (!email || !password || !newPassword) {
    res.status(403).send("Please fill all the data");
  } else {
    try {
      const user = await Users.findOne({ email });
      if (!user) {
        res.status(401).send("User not found");
      } else {
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
          res.status(401).send("Invalid password");
        } else {
          const salt = await bcrypt.genSalt(saltround);
          const hashPassword = await bcrypt.hash(newPassword, salt);
          user.password = hashPassword;
          await user.save();
          res.status(200).send("Password reset successful");
        }
      }
    } catch (error) {
      console.log(error);
      res.status(500).send("Server error");
    }
  }
});

router.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  if (!email) {
    res.status(403).send("Please provide an email address");
  } else {
    try {
      const user = await Users.findOne({ email });
      if (!user) {
        res.status(401).send("User not found");
      } else {
        // Generate a random temporary password
        const temporaryPassword = Math.random().toString(36).slice(-8);

        // Hash the temporary password
        const salt = await bcrypt.genSalt(saltround);
        const hashPassword = await bcrypt.hash(temporaryPassword, salt);

        // Update the user's password with the temporary password
        user.password = hashPassword;
        await user.save();

        // Send the temporary password to the user via email
        const mailData = {
          from: process.env.EMAIL,
          to: email,
          subject: "Password Reset",
          text: `Your temporary password is: ${temporaryPassword}`,
        };

        transporter.sendMail(mailData, (error, info) => {
          if (error) {
            console.log(error);
            res.status(500).send("Server error");
          } else {
            res.status(200).send("Temporary password sent to your email");
          }
        });
      }
    } catch (error) {
      console.log(error);
      res.status(500).send("Server error");
    }
  }
});


// router.get("/admin-only", authRole, (req, res) => {
//   // Only admin users can access this route
//   res.send("Admin-only route");
// });

// router.get("/getuser", authUser, async (req, res) => {
//   try {
//     const userid = req.id;
//     const user = await Users.findById(userid);
//     res.status(200).send(user);
//   } catch (error) {
//     console.log(error);
//     res.status(401).send("Server error");
//   }
// });

module.exports = router;
