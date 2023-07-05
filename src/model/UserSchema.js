const mongoose = require("mongoose");
const validator = require("validator");
//  the first step will be always create a Schema
const UserSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },
    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user",
    },
    email: {
      required: true,
      unique: true,
      type: String,
      validate(data) {
        if (!validator.isEmail(data)) {
          throw new Error("Email is not valid");
        }
      },
    },
    password: {
      required: true,
      minlength: 5,
      type: String,
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    otp: {
      required: true,
      type: Number,
    },
    resetToken: {
      type: String,
      default: null,
    },
    resetTokenExpiration: {
      type: Date,
      default: null,
    },
  },
  { timestamps: true }
);

//  here we are creating model / collection
const Users = new mongoose.model("Users", UserSchema);

module.exports = Users;
