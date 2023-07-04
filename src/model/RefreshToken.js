const mongoose = require("mongoose");

const RefreshTokenSchema = new mongoose.Schema({
    token: {
        type: String,
        required: true,
        unique: true,
    },
});

const RefreshToken = new mongoose.model("RefreshToken", RefreshTokenSchema);

module.exports = RefreshToken;