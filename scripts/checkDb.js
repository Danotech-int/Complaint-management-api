const path = require("node:path");
const mongoose = require("mongoose");
require("dotenv").config({ path: path.join(__dirname, "../.env") });
const connectDB = require("../config/db.js");

async function checkDB() {
  try {
    await connectDB();
    await mongoose.connection.db.admin().ping();
    console.log("MongoDB ping succeeded.");
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  } finally {
    await mongoose.disconnect();
  }
}

checkDB();
