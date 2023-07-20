const mongoose = require("mongoose");
const validator = require("validator");
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
    isBlocked: {
      type: Boolean,
      default: false,
    },
    isKYC: {
      type: Boolean,
      default: false,
    },
    otp: {
      required: true,
      type: Number,
    },
    loginotp: {
      required: false,
      type: Number,
      default: "",
    },
    balance: {
      type: Number,
      default: 0,
    },
    transactionIds: {
      type: [Object],
      default: [],
    },
  },
  { timestamps: true }
);

//  here we are creating model / collection
const Users = new mongoose.model("Users", UserSchema);

module.exports = Users;
