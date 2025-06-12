const nodemailer = require('nodemailer');
const { EMAIL_VERIFICATION_EXPIRATION_MINUTES } = require('@/config/constants');

async function sendVerificationEmail(toEmail, code) {
    const appBaseUrl = process.env.APP_BASE_URL || `http://localhost:${process.env.PORT || 3000}`;
    const verificationUrl = `${appBaseUrl}/api/verify-email?code=${code}`;

    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });

    const mailOptions = {
        from: `"Konoha Minecraft Server Access Portal" <${process.env.EMAIL_USER}>`,
        to: toEmail,
        subject: "Verify your email for Konoha Minecraft Server",
        html: `
            <div style="font-family: sans-serif; line-height: 1.6;">
                <h2> Welcome to the Konoha Minecraft Server Access Portal! </h2>
                <p> To verify your email address and continue the registration process,
                please click the link below: </p>
                <p>
                    <a href="${verificationUrl}"
                       target="_blank"
                       style="background-color: #4CAF50;
                              color: white;
                              padding: 10px 20px;
                              text-decoration: none;">Verify Email</a>
                </p>
                <p>This link will expire in ${EMAIL_VERIFICATION_EXPIRATION_MINUTES} 
                   minutes for security purposes.
                </p>
                <hr />
                <p>If you did not request this, please ignore this email.</p>
            </div>
        `
    };

    const info = await transporter.sendMail(mailOptions);
    console.log(`Verification email sent: ${info.messageId}`);
    console.log(`Verification URL (for local testing): ${verificationUrl}`);
}

module.exports = { sendVerificationEmail };
