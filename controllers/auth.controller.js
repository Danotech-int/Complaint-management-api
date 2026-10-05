const bcrypt = require("bcryptjs");

const {
  createHash,
  timingSafeEqual,
  randomBytes,
  randomInt,
} = require("node:crypto");

const User = require("../models/user.model.js");
const PasswordReset = require("../models/passwordReset.model.js");

const generateToken = require("../utils/generateToken.js");
const AppError = require("../utils/app-error.js");

const { sendPasswordResetOtp } = require("../services/emailService.js");

const generateOtp = () => {
  return randomInt(100000, 1000000).toString();
};

const hashValue = (value) => {
  return createHash("sha256").update(value).digest("hex");
};

const toPublicUser = (user) => {
  const publicUser = user.toObject();
  delete publicUser.password;
  return publicUser;
};

const register = async (req, res, next) => {
  try {
    const { firstName, lastName, userName, email, password } = req.body;

    if (!firstName || !lastName || !userName || !email || !password) {
      throw new AppError("All fields are required", 400);
    }

    if (
      typeof password !== "string" ||
      password.length < 6 ||
      password.length > 20
    ) {
      throw new AppError("Password must be between 6 and 20 characters", 400);
    }

    const normalizedEmail = email.trim().toLowerCase();
    const normalizedUserName = userName.trim().toLowerCase();

    const existingUser = await User.findOne({
      $or: [{ email: normalizedEmail }, { userName: normalizedUserName }],
    });

    if (existingUser) {
      throw new AppError(
        "User with this email or username already exists",
        409,
      );
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      firstName,
      lastName,
      userName: normalizedUserName,
      email: normalizedEmail,
      password: hashedPassword,
    });

    const token = generateToken(user._id);

    return res.status(201).json({
      message: "Registration successful",
      token,
      user: toPublicUser(user),
    });
  } catch (error) {
    return next(error);
  }
};

const registerAdmin = async (req, res, next) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      throw new AppError("Name, email and password are required", 400);
    }

    if (
      typeof password !== "string" ||
      password.length < 6 ||
      password.length > 20
    ) {
      throw new AppError(
        "Password must be between 6 and 20 characters",
        400,
      );
    }

    const normalizedEmail = email.trim().toLowerCase();
    const trimmedName = name.trim();

    const nameParts = trimmedName.split(/\s+/);
    const firstName = nameParts[0];
    const lastName = nameParts.slice(1).join(" ") || firstName;

    const baseUserName = trimmedName
      .toLowerCase()
      .replace(/[^a-z0-9]/g, "");

    let userName = baseUserName;
    let counter = 1;

    while (await User.findOne({ userName })) {
      userName = `${baseUserName}${counter}`;
      counter++;
    }

    const existingUser = await User.findOne({
      email: normalizedEmail,
    });

    if (existingUser) {
      throw new AppError("A user with this email already exists", 409);
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      firstName,
      lastName,
      userName,
      email: normalizedEmail,
      password: hashedPassword,
      role: "ADMIN",
    });

    const token = generateToken(user._id);

    return res.status(201).json({
      message: "Admin registration successful",
      token,
      user: toPublicUser(user),
    });
  } catch (error) {
    return next(error);
  }
};

const login = async (req, res, next) => {
  try {
    const { email, userName, password } = req.body;
    const loginIdentifier = email || userName;

    if (!loginIdentifier || !password) {
      throw new AppError(
        "Email or username and password are required",
        400,
      );
    }

    const normalizedIdentifier = loginIdentifier.trim().toLowerCase();

    const user = await User.findOne({
      $or: [
        { email: normalizedIdentifier },
        { userName: normalizedIdentifier },
      ],
    }).select("+password");

    if (!user) {
      throw new AppError("User not found, Please Register", 404);
    }

    if (!user.isActive) {
      throw new AppError("Your account has been deactivated", 403);
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      throw new AppError("Invalid email or password", 401);
    }

    const token = generateToken(user._id);

    return res.status(200).json({
      message: "Login successful",
      token,
      user: toPublicUser(user),
    });
  } catch (error) {
    return next(error);
  }
};

const forgotPassword = async (req, res, next) => {
  try {
    const email = req.body?.email;

    if (typeof email !== "string" || !email.trim()) {
      throw new AppError("Email is required", 400);
    }

    const normalizedEmail = email.trim().toLowerCase();

    const user = await User.findOne({
      email: normalizedEmail,
    });

    const genericMessage =
      "If an account exists for this email, a verification code has been sent.";

    // Do not reveal whether the email exists.
    if (!user || !user.isActive) {
      return res.status(200).json({
        message: genericMessage,
      });
    }

    // Invalidate previous unused password-reset requests.
    await PasswordReset.updateMany(
      {
        userId: user._id,
        used: false,
      },
      {
        $set: {
          used: true,
        },
      },
    );

    const otp = generateOtp();
    const otpHash = hashValue(otp);
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await PasswordReset.create({
      userId: user._id,
      otpHash,
      expiresAt,
    });

    await sendPasswordResetOtp(user.email, otp);

    return res.status(200).json({
      message: genericMessage,
    });
  } catch (error) {
    return next(error);
  }
};

const verifyResetOTP = async (req, res, next) => {
  try {
    const { email, otp } = req.body;

    if (typeof email !== "string" || !email.trim()) {
      throw new AppError("Email is required", 400);
    }

    if (typeof otp !== "string" || !/^\d{6}$/.test(otp)) {
      throw new AppError("Verification code must be 6 digits", 400);
    }

    const normalizedEmail = email.trim().toLowerCase();

    const user = await User.findOne({
      email: normalizedEmail,
      isActive: true,
    });

    if (!user) {
      throw new AppError("Invalid or expired verification code", 400);
    }

    const resetRequest = await PasswordReset.findOne({
      userId: user._id,
      used: false,
      otpVerifiedAt: null,
    }).sort({ createdAt: -1 });

    if (!resetRequest) {
      throw new AppError("Invalid or expired verification code", 400);
    }

    if (resetRequest.expiresAt <= new Date()) {
      throw new AppError("Invalid or expired verification code", 400);
    }

    if (resetRequest.attempts >= 5) {
      throw new AppError(
        "Too many verification attempts. Please request a new code.",
        429,
      );
    }

    // Count every verification attempt, including failed attempts.
    await PasswordReset.updateOne(
      { _id: resetRequest._id },
      { $inc: { attempts: 1 } },
    );

    const expectedHash = Buffer.from(resetRequest.otpHash, "hex");
    const receivedHash = Buffer.from(hashValue(otp), "hex");

    const valid =
      expectedHash.length === receivedHash.length &&
      timingSafeEqual(expectedHash, receivedHash);

    if (!valid) {
      throw new AppError("Invalid or expired verification code", 400);
    }

    const resetToken = randomBytes(32).toString("hex");
    const resetTokenHash = hashValue(resetToken);
    const resetTokenExpiresAt = new Date(
      Date.now() + 10 * 60 * 1000,
    );

    await PasswordReset.updateOne(
      { _id: resetRequest._id },
      {
        $set: {
          otpVerifiedAt: new Date(),
          resetTokenHash,
          resetTokenExpiresAt,
        },
      },
    );

    return res.status(200).json({
      message: "Verification code verified successfully",
      resetToken,
    });
  } catch (error) {
    return next(error);
  }
};

const resetPassword = async (req, res, next) => {
  try {
    const { resetToken, newPassword } = req.body;

    if (typeof resetToken !== "string" || !resetToken.trim()) {
      throw new AppError("Reset token is required", 400);
    }

    if (
      typeof newPassword !== "string" ||
      newPassword.length < 6 ||
      newPassword.length > 20
    ) {
      throw new AppError(
        "Password must be between 6 and 20 characters",
        400,
      );
    }

    const resetTokenHash = hashValue(resetToken);

    const resetRequest = await PasswordReset.findOne({
      resetTokenHash,
      used: false,
      otpVerifiedAt: { $ne: null },
      resetTokenExpiresAt: {
        $gt: new Date(),
      },
    });

    if (!resetRequest) {
      throw new AppError(
        "Reset session is invalid or has expired. Please request a new code.",
        400,
      );
    }

    const user = await User.findById(resetRequest.userId);

    if (!user || !user.isActive) {
      throw new AppError(
        "Reset session is invalid or has expired.",
        400,
      );
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await User.updateOne(
      { _id: user._id },
      {
        $set: {
          password: hashedPassword,
        },
      },
    );

    // Invalidate all outstanding reset requests for this user.
    await PasswordReset.updateMany(
      {
        userId: user._id,
        used: false,
      },
      {
        $set: {
          used: true,
          resetTokenHash: null,
          resetTokenExpiresAt: null,
        },
      },
    );

    return res.status(200).json({
      message: "Password reset successful",
    });
  } catch (error) {
    return next(error);
  }
};

module.exports = {
  register,
  registerAdmin,
  login,
  forgotPassword,
  verifyResetOTP,
  resetPassword,
};