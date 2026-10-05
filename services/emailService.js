const { Resend } = require("resend");

const resend = new Resend(process.env.RESEND_API_KEY);

const sendPasswordResetOtp = async (email, otp) => {
  await resend.emails.send({
    from: process.env.RESEND_FROM_EMAIL,
    to: email,
    subject: "ComplaintsHQ Password Reset OTP",
    html: `
      <div style="font-family: Arial, sans-serif;">
        <h2>Password Reset</h2>

        <p>Your ComplaintsHQ verification code is:</p>

        <h1 style="letter-spacing: 8px;">${otp}</h1>

        <p>This code will expire in 10 minutes.</p>

        <p>
          If you did not request a password reset, you can ignore this email.
        </p>
      </div>
    `,
  });
};

module.exports = {
  sendPasswordResetOtp,
};