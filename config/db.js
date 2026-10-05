const mongoose = require("mongoose");

const connectDB = async () => {
  const uri = process.env.MONGO_URI?.trim();
  if (!uri) {
    throw new Error("MONGO_URI is missing. Set it in complaint-management-api/.env.");
  }

  try {
    const connection = await mongoose.connect(uri, {
      serverSelectionTimeoutMS: 10000,
      connectTimeoutMS: 10000,
    });

    console.log(`MongoDB connected: ${connection.connection.host}`);
    return connection;
  } catch (error) {
    // Driver errors can contain connection strings. Keep credentials out of logs.
    let message = error.message.replace(/mongodb(?:\+srv)?:\/\/\S+/gi, "[redacted MongoDB URI]");
    if (/TLS|SSL|alert number 80/i.test(message)) {
      message += "\nCheck the Atlas project's Network Access IP access list for your current public IP, confirm the cluster is running, and check whether your VPN or firewall blocks MongoDB traffic on port 27017.";
    }
    throw new Error(`MongoDB connection failed: ${message}`, { cause: error });
  }
};

module.exports = connectDB;
