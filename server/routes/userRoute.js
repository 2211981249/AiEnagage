const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const User = require("../models/userModal.js");
const router = express.Router();
require("dotenv").config();
const { VapiClient } = require("@vapi-ai/server-sdk");
const nodemailer = require("nodemailer");
const otpStore = {};
const JWT_SECRET = process.env.JWT_SECRET;
const authMiddleware = require("../middlewares/authMiddleware");
const SubUser = require("../models/subUserSchema.js");
const crypto = require("crypto");
const CallLog = require("../models/CallLog.js");
const multer = require("multer");
const subUserSchema = require("../models/subUserSchema.js");
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

const twilio = require("twilio");
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const client = twilio(accountSid, authToken);

const axios = require("axios");
const VAPI_API_KEY = process.env.VAPI_API_KEY;
const API_URL = "https://api.vapi.ai/call";
const SENDGRID_API_KEY = process.env;
const sgMail = require("@sendgrid/mail");
sgMail.setApiKey(SENDGRID_API_KEY);

router.post("/signup", async (req, res) => {
  const { name, email, password, phone } = req.body;

  try {
    // Check if the user already exists
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: "User already exists" });
    }

    // Generate a random 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore[email] = otp; // Store the OTP for later verification

    // Prepare email content
    const msg = {
      to: email,
      from: "choudhardiv@gmail.com",
      subject: "Your OTP for Signup - OTP Mazer",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px; background-color: #f9f9f9;">
          <h2 style="text-align: center; color: #007BFF;">OTP Mazer</h2>
          <p style="font-size: 16px; color: #333;">Hi there,</p>
          <p style="font-size: 16px; color: #333;">Thank you for signing up with <strong>OTP Mazer</strong>! To complete your registration, please use the OTP below:</p>
          <div style="text-align: center; margin: 20px 0;">
            <p style="font-size: 24px; font-weight: bold; background-color: #007BFF; color: white; padding: 10px; border-radius: 4px; display: inline-block;">${otp}</p>
          </div>
          <p style="font-size: 16px; color: #333;">Please enter this OTP within the next 10 minutes to complete your signup process. If you did not request this, please ignore this email.</p>
          <p style="font-size: 16px; color: #333;">Best regards,<br>OTP Mazer Team</p>
          <footer style="text-align: center; margin-top: 20px; font-size: 12px; color: #888;">
            © 2024 OTP Mazer. All rights reserved.
          </footer>
        </div>
      `,
    };

    // Send the email
    await sgMail.send(msg);
    res.status(200).json({ message: "OTP sent to email. Please verify." });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server Error" });
  }
});
// Route to verify OTP and complete the registration
router.post("/verify-otp", async (req, res) => {
  const { name, email, password, phone, otp } = req.body;

  try {
    // Verify OTP
    if (otpStore[email] !== otp) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    // OTP is valid, remove it from store
    delete otpStore[email];

    // Register the new user
    const newUser = new User({ name, email, password, phone });
    await newUser.save();

    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server Error" });
  }
});

const verifyAndFetchUser = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token)
      return res
        .status(401)
        .json({ message: "Access denied. No token provided." });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    req.role = decoded.role;

    let user;
    if (req.role === "subuser") {
      user = await SubUser.findById(req.userId).populate("adminId");
      if (!user) return res.status(404).json({ message: "SubUser not found." });
      req.twilioCredentials = {
        token: user.adminId.twilioToken,
        sid: user.adminId.twilioSid,
        phone: user.adminId.twilioNum,
      };
    } else {
      user = await User.findById(req.userId);
      if (!user) return res.status(404).json({ message: "User not found." });
      req.twilioCredentials = {
        token: user.twilioToken,
        sid: user.twilioSid,
        phone: user.twilioNum,
      };
    }
    next();
  } catch (error) {
    console.error("Error verifying token:", error);
    res.status(400).json({ message: "Invalid token." });
  }
};

router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    // First check in User collection
    let user = await User.findOne({ email });
    let role = "user";

    if (!user) {
      // If not found, check in SubUser collection
      user = await SubUser.findOne({ email });
      role = "subuser";

      if (!user) {
        res.flash("error", "Invalid username or password");
        return res
          .status(401)
          .json({ message: "Invalid username or password" });
      }
    }

    // Check if the password matches
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      res.flash("error", "Invalid username or password");
      return res.status(401).json({ message: "Invalid username or password" });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, role: user.role || role },
      JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.flash("success", "Login successful");
    return res.status(200).json({
      message: "Login successful",
      success: true,
      token,
    });
  } catch (err) {
    console.error(err);
    res.flash("error", "Server Error");
    return res.status(500).json({ message: "Server Error" + err });
  }
});

router.get("/validate", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    res.flash("No token provided");
    return res.status(401).json({ valid: false, message: "No token provided" });
  }

  jwt.verify(token, JWT_SECRET, async (err, data) => {
    if (err) {
      res.flash("Invalid token");
      return res.status(401).json({ valid: false, message: "Invalid token" });
    }

    let user = await User.findById(data.userId);
    if (!user) {
      user = await SubUser.findById(data.userId);
    }

    if (!user) {
      res.flash("User not found");
      return res.status(404).json({ valid: false, message: "User not found" });
    }

    return res.status(200).json({ valid: true, role: user.role, data: user });
  });
});

router.get("/validate-profile", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    res.flash("No token provided");
    return res.status(401).json({ valid: false, message: "No token provided" });
  }

  jwt.verify(token, JWT_SECRET, async (err, data) => {
    if (err) {
      res.flash("error", "Invalid token");
      return res.status(401).json({ valid: false, message: "Invalid token" });
    }

    let userData = await User.findById(data.userId);
    if (!userData) {
      userData = await SubUser.findById(data.userId);
    }

    if (!userData) {
      res.flash("User not found");
      return res.status(404).json({ valid: false, message: "User not found" });
    }

    return res.status(200).json({ valid: true, data: userData });
  });
});

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization.split(" ")[1];
  if (!token) {
    res.flash("Access denied");
    return res.status(401).json({ message: "Access denied" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    req.role = decoded.role; // You can access role if needed
    next();
  } catch (error) {
    return res.status(400).json;
  }
};

router.get("/users", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user || user.role !== "admin") {
      res.flash("Access denied");
      return res.status(403).json({ message: "Access denied" });
    }
    const users = await User.findOne({ email: user.email }).populate(
      "subUsers"
    );
    res.status(200).json(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.flash("error", "Server Error");
    res.status(500).json({ message: "Server Error" });
  }
});

router.post("/update-profile", verifyToken, async (req, res) => {
  const { field, value } = req.body;
  try {
    let user = await User.findById(req.userId);
    if (!user) {
      user = await SubUser.findById(req.userId);
    }

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    user[field] = value;
    await user.save();
    res
      .status(200)
      .json({ message: "Profile updated successfully", data: user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error updating profile" });
  }
});

router.get("/twilio/messages", verifyAndFetchUser, async (req, res) => {
  try {
    const { token, sid } = req.twilioCredentials;
    if (!token || !sid) {
      return res
        .status(400)
        .json({ message: "Twilio credentials not configured." });
    }

    const client = twilio(sid, token);

    const days = parseInt(req.query.days) || 15;
    const today = new Date();
    const startDate = new Date();
    startDate.setDate(today.getDate() - days);

    const messages = await client.messages.list({
      dateSentAfter: startDate,
      dateSentBefore: today,
      limit: 100,
    });

    const totalLength = messages.length;
    const latestThreeMessages = messages.slice(0, 3);

    res.json({ latestThreeMessages, totalLength });
  } catch (error) {
    console.error("Error fetching messages:", error);
    res.status(500).json({ error: "Error fetching message details" });
  }
});

router.post("/add-subUser", async (req, res) => {
  try {
    const { name, email, password, phone, credit } = req.body;

    // Check if sub-user with the same email already exists in SubUser
    const checkSubUser = await SubUser.findOne({ email });
    if (checkSubUser) {
      res.flash("Sub-user with this email already exists");
      return res
        .status(401)
        .json({ message: "Sub-user with this email already exists" });
    }

    // Check if the email exists in the User model
    const checkUser = await User.findOne({ email });
    if (checkUser) {
      res.flash("User with this email already exists");
      return res
        .status(401)
        .json({ message: "User with this email already exists" });
    }

    // Get token and verify it
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      res.flash("Authorization token missing");
      return res.status(403).json({ message: "Authorization token missing" });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      res.flash("Invalid or expired token");
      return res.status(401).json({ message: "Invalid or expired token" });
    }
    const adminData = await User.findById(decoded.userId);
    if (!adminData || adminData.role !== "admin") {
      res.flash("No permission to add sub-user");
      return res.status(401).json({ message: "No permission to add sub-user" });
    }

    if (adminData.credits < credit) {
      return res
        .status(403)
        .json({ message: "Insufficient credits to add a sub-user" });
    }

    adminData.credits -= credit;
    // Create new sub-user
    const newSubUser = new SubUser({
      name,
      email,
      password,
      phone,
      adminId: adminData._id,
      credit,
      totalCredit: credit,
    });

    const resetToken = crypto.randomBytes(32).toString("hex");
    const resetTokenExpiry = Date.now() + 3600000;
    newSubUser.resetToken = resetToken;
    newSubUser.resetTokenExpiry = resetTokenExpiry;

    await newSubUser.save();

    adminData.subUsers.push(newSubUser._id);
    await adminData.save();

    const resetUrl = `https://www.aiengage.ai/passwordreset.html?token=${resetToken}&email=${newSubUser.email}`;
    await sendPasswordResetEmail(newSubUser.email, resetUrl);

    res
      .status(201)
      .json({ message: "Sub-user added successfully", user: newSubUser });
  } catch (error) {
    console.error("Error adding sub-user:", error);
    res.status(500).json({ message: "Server error" });
  }
});
async function sendPasswordResetEmail(email, resetUrl) {
  const msg = {
    to: email,
    from: "choudhardiv@gmail.com", // Your verified sender email in SendGrid
    subject: "Change Your Password",
    html: `
      <p>Please click the following link to change your password:</p>
      <a href="${resetUrl}">Change Your Password</a>
      <p>This link will expire in <strong>5 minutes</strong>.</p>
    `,
  };

  try {
    await sgMail.send(msg);
  } catch (error) {
    console.error("Error sending password reset email:", error);
    throw new Error("Email sending failed");
  }
}

router.post("/reset-password", async (req, res) => {
  try {
    const { token, email, newPassword } = req.body;

    const subUser = await SubUser.findOne({
      email,
      resetToken: token,
      resetTokenExpiry: { $gt: Date.now() },
    });

    if (!subUser) {
      return res
        .status(400)
        .json({ message: "Invalid or expired token. Please try again." });
    }

    // Update the password
    subUser.password = newPassword;
    subUser.resetToken = undefined;
    subUser.resetTokenExpiry = undefined;
    await subUser.save();

    res.status(200).json({ message: "Password reset successfully" });
  } catch (error) {
    console.error("Error resetting password:", error);
    res.status(500).json({
      message: "An unexpected server error occurred. Please try again later.",
    });
  }
});

router.post("/forgot-password", async (req, res) => {
  const { email } = req.body;

  try {
    let user = await User.findOne({ email });
    let isSubUser = false;

    if (!user) {
      user = await SubUser.findOne({ email });
      isSubUser = true; // Mark this as a SubUser if found here
    }

    // If email not found in both collections, return an error
    if (!user) {
      return res.json({ message: "User not Exists!", status: "false" });
    }

    // Generate token with secret that includes the user's password hash
    const secret = process.env.JWT_SECRET + user.password;
    const token = jwt.sign({ email: user.email, id: user._id }, secret, {
      expiresIn: "30m",
    });

    // Password reset link
    const link = `https://www.aiengage.ai/passwordForgot.html?id=${user._id}&token=${token}`;

    const msg = {
      to: email,
      from: "choudhardiv@gmail.com",
      subject: "Password Reset - Mazer",
      html: `
      <!DOCTYPE html>
      <html lang="en">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <style>
              body {
                  font-family: Arial, sans-serif;
                  background-color: #f4f4f4;
                  margin: 0;
                  padding: 20px;
              }
              .container {
                  background-color: #ffffff;
                  border-radius: 8px;
                  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                  padding: 20px;
                  max-width: 600px;
                  margin: auto;
              }
              h1 {
                  color: #004aad;
                  text-align: center;
              }
              p {
                  color: #333333;
                  line-height: 1.6;
              }
              .button {
                  display: inline-block;
                  background-color: #004aad;
                  color: white;
                  padding: 10px 20px;
                  text-decoration: none;
                  border-radius: 5px;
                  margin: 20px 0;
              }
              .footer {
                  text-align: center;
                  margin-top: 20px;
                  font-size: 12px;
                  color: #777777;
              }
          </style>
      </head>
      <body>
          <div class="container">
              <h1>Password Reset Request</h1>
              <p>Hi there,</p>
              <p>We received a request to reset your password for your account on <strong>Mazer</strong>.</p>
              <p>To reset your password, please click the link below:</p>
              <a href="${link}" class="button">Reset Password</a>
              <p>This link will expire in <strong>30 minutes</strong>.</p>
              <p>If you did not request a password reset, please ignore this email.</p>
              <p>Thank you!</p>
              <div class="footer">
                  <p>&copy; ${new Date().getFullYear()} Mazer. All rights reserved.</p>
              </div>
          </div>
      </body>
      </html>
      `,
    };

    // Send the email
    await sgMail.send(msg);
    return res.json({ status: "Success", link });
  } catch (error) {
    console.error("Forgot password Error: ", error);
    return res.status(500).json({ status: "Server error" });
  }
});

// router.get("/forgot-password/:id/:token", async (req, res) => {
//   const { id, token } = req.params;

//   try {
//     const oldUser = await User.findById(id);
//     if (!oldUser) {
//       return res
//         .status(400)
//         .json({ message: "User Not Exists!", success: false });
//     }

//     // const secret = JWT_SECRET + oldUser.password;
//     const secret = process.env.JWT_SECRET + oldUser.password;
//     try {
//       jwt.verify(token, secret);
//       return res.status(200).json({
//         message: "Verified",
//         success: true,
//       });
//     } catch (error) {
//       return res
//         .status(400)
//         .json({ message: "Token not verified", success: false });
//     }
//   } catch (error) {
//     return res.status(500).json({ message: "Server error", success: false });
//   }
// });

router.post("/forgot-password/:id/:token", async (req, res) => {
  const { id, token } = req.params;
  const { password } = req.body;

  try {
    // Check in the User model
    let user = await User.findOne({ _id: id });

    if (!user) {
      // Check in the SubUser model if not found in User
      user = await SubUser.findOne({ _id: id });
      if (!user) {
        return res
          .status(400)
          .json({ message: "User Not Found", success: false });
      }
    }

    // Generate secret key using user's current password
    const secret = process.env.JWT_SECRET + user.password;

    // Verify the token
    jwt.verify(token, secret);

    // Encrypt new password
    const encryptedPassword = await bcrypt.hash(password, 10);

    // Update password in the respective model
    const model = user instanceof User ? User : SubUser;

    await model.updateOne(
      { _id: id },
      { $set: { password: encryptedPassword } }
    );

    return res.status(200).json({ message: "Password Updated", success: true });
  } catch (error) {
    console.error("Error resetting password:", error);
    return res.status(500).json({ message: "Server Error", success: false });
  }
});

// router.post("/forgot-password/:id/:token", async (req, res) => {
//   const { id, token } = req.params;
//   const { password } = req.body;
//   try {
//     const oldUser = await User.findOne({ _id: id });
//     if (!oldUser) {
//       return res
//         .status(400)
//         .json({ message: "User Not Exists!", success: false });
//     }

//     // const secret = JWT_SECRET + oldUser.password;
//     const secret = process.env.JWT_SECRET + oldUser.password;
//     try {
//       jwt.verify(token, secret);
//       const encryptedPassword = await bcrypt.hash(password, 10);
//       await User.updateOne(
//         {
//           _id: id,
//         },
//         {
//           $set: {
//             password: encryptedPassword,
//           },
//         }
//       );
//       res.status(200).json({ message: "Password Update", success: true });
//     } catch (error) {
//       return res
//         .status(400)
//         .json({ message: "Something Went Wrong", success: false });
//     }
//   } catch (error) {
//     return res.status(500).json({ message: "Server error", success: false });
//   }
// });

router.get("/check-credit", verifyToken, async (req, res) => {
  try {
    const { userId, role } = req;
    let user;
    let adminUser;
    // For storing admin details if the role is subuser

    if (role === "admin") {
      // Find the user directly if they are an admin
      user = await User.findById(userId);
    } else if (role === "subuser") {
      // Find the subuser
      user = await SubUser.findById(userId);
      if (user && user.adminId) {
        // Find the corresponding admin using adminId from the subuser document
        adminUser = await User.findById(user.adminId);
      }
    } else if (role === "super_admin") {
      // Fetch user details directly for super admin
      user = await User.findById(userId);

      // Send details directly for super_admin
      if (!user) {
        return res.status(404).json({ message: "Super admin user not found" });
      }
      const response = {
        message: "Sufficient credits available",
        vapiPhoneNumberId: user.vapiPhoneNumberId,
        userId: userId,
      };

      return res.status(200).json(response);
    }
    if (!user || (role === "subuser" && !adminUser)) {
      return res.status(404).json({ message: "User not found" });
    }

    // Check if credits are sufficient
    const credits = role === "admin" ? user.credits : user.credit;
    if (credits < 1) {
      return res.status(403).json({ message: "Insufficient credits" });
    }

    // Respond with vapiPhoneNumberId if available
    const response = {
      message: "Sufficient credits available",
      vapiPhoneNumberId:
        role === "admin" ? user.vapiPhoneNumberId : adminUser.vapiPhoneNumberId,
      userId: userId,
    };

    res.status(200).json(response);
  } catch (error) {
    console.error("Error checking credits: ", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// router.get("/update-credit", verifyToken, async (req, res) => {
//   try {
//     const { userId, role } = req;
//     const { sid } = req.query; // Retrieve the callSid from the request query
//     let user;

//     console.log(sid)
//     if (!sid) {
//       return res.status(400).json({ message: "callSid is required" });
//     }

//     // Check if the role is 'admin' or 'subuser'
//     if (role === "admin") {
//       user = await User.findById(userId);
//     } else if (role === "subuser") {
//       user = await SubUser.findById(userId);
//       if (user && user.adminId) {
//         adminUser = await User.findById(user.adminId);
//       }
//     } else if (role === "super_admin") {
//       user = await User.findById(userId);
//       return res.json({
//         message: "Credit updated successfully",
//         credits: user.credits,
//       });
//     }

//     if (!user) {
//       return res.status(404).json({ message: "User not found" });
//     }

//     let admin;
//     if (role === "subuser") {
//       admin = user.adminId;
//       if (!admin) {
//         return res
//           .status(404)
//           .json({ message: "Admin not found for this sub-user" });
//       }
//     }

//     console.log("Commmememememmemm")

//     const superAdminUser = await User.findOne({ role: "super_admin" });
//     const tokenCall = superAdminUser.tokenCall;
//     const client1 = new VapiClient({
//       token: tokenCall,
//     });

//     const vapiResponse = await client1.calls.list();
//     console.log(vapiResponse)
//     const callDetails = vapiResponse.find(
//       (call) => call.phoneCallProviderId === sid
//     );

//     console.log(callDetails);
//     const creditToDeduct = 1;
//     const deductCredit = (account, amount) => {
//       if (account.credits && account.credits >= amount) {
//         account.credits -= amount;
//       } else if (account.credit && account.credit >= amount) {
//         account.credit -= amount;
//       }
//     };

//     // Deduct the calculated credit from the user
//     deductCredit(user, creditToDeduct);

//     // Save the updated user information
//     await user.save();

//     const remainingCredits = user.credits || user.credit;
//     return res.json({
//       message: "Credit updated successfully",
//       credits: remainingCredits,
//       deductedCredit: creditToDeduct,
//       callDurationInMinutes: callDurationInMinutes,
//     });
//   } catch (error) {
//     console.error("Error updating credits:", error);
//     return res.status(500).json({ message: "Internal Server Error" });
//   }
// });

router.get("/update-credit", verifyToken, async (req, res) => {
  try {
    const { userId, role } = req;
    const { sid } = req.query;
    let user;
    if (!sid) {
      return res.status(400).json({ message: "callSid is required" });
    }

    // Determine the user based on the role
    if (role === "admin") {
      user = await User.findById(userId);
    } else if (role === "subuser") {
      user = await SubUser.findById(userId);
      if (user && user.adminId) {
        adminUser = await User.findById(user.adminId);
      }
    } else if (role === "super_admin") {
      user = await User.findById(userId);
      return res.json({
        message: "Credit updated successfully",
        credits: user.credits,
      });
    }

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Fetch the super admin user for API token
    const superAdminUser = await User.findOne({ role: "super_admin" });
    const tokenCall = superAdminUser.tokenCall;
    const client1 = new VapiClient({
      token: tokenCall,
    });

    // Fetch call details
    const vapiResponse = await client1.calls.list();
    const callDetails = vapiResponse.find((call) => call.id === sid);
    if (!callDetails || !callDetails.messages) {
      return res.status(404).json({
        message: "Call details or messages not found for the provided SID",
      });
    }

    // Process the messages array
    let totalMinutes = 0;
    callDetails.messages.forEach((message) => {
      const durationInMinutes = Math.floor(message.duration || 0); // Convert ms to minutes
      totalMinutes += durationInMinutes;
    });

    totalMinutes = totalMinutes / 600;
    let creditsToDeduct = totalMinutes * 0.0145;
    if (creditsToDeduct > 0) {
      const deductCredit = (account, amount) => {
        if (account.credits && account.credits >= amount) {
          account.credits -= amount;
        } else if (account.credit && account.credit >= amount) {
          account.credit -= amount;
        }
      };
      deductCredit(user, creditsToDeduct);
      await user.save();
      const remainingCredits = user.credits || user.credit;
      return res.json({
        message: "Credit updated successfully",
        credits: remainingCredits,
        deductedCredit: creditsToDeduct,
        totalMinutes,
      });
    } else {
      return res.json({
        message:
          "No credits were deducted as the call duration was less than 3 minutes.",
        totalMinutes,
      });
    }
  } catch (error) {
    console.error("Error updating credits:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
});

router.delete("/subuser/:id", async (req, res) => {
  try {
    const subUserId = req.params.id;

    // Find and delete the sub-user
    const deletedSubUser = await SubUser.findByIdAndDelete(subUserId);

    if (!deletedSubUser) {
      return res.status(404).json({ message: "Sub-user not found" });
    }

    // Extract sub-user's remaining credits
    const subUserCredits = deletedSubUser.credit || 0; // Default to 0 if no credits

    // Find the admin associated with the sub-user
    const admin = await User.findById(deletedSubUser.adminId); // Get the admin from the deleted sub-user

    if (!admin) {
      return res.status(404).json({ message: "Admin not found" });
    }

    // Update the admin's credits
    const updatedAdmin = await User.findByIdAndUpdate(
      admin._id,
      { $inc: { credits: subUserCredits } }, // Increment the admin's credits
      { new: true } // Return the updated admin
    );

    // Remove the sub-user reference from the admin's subUsers array
    await User.findByIdAndUpdate(
      admin._id,
      { $pull: { subUsers: subUserId } }, // Remove sub-user from admin's subUsers array
      { new: true } // Optional: return the updated admin document if needed
    );

    res.status(200).json({
      message: "Sub-user deleted successfully",
      adminCredits: updatedAdmin.credits, // Return updated admin credits if needed
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

router.post("/check-bulk-credit", verifyToken, async (req, res) => {
  try {
    const { userId, role } = req;
    const { callCount } = req.body; // Number of calls to be made in bulk

    let user, adminData;

    if (role === "admin") {
      user = await User.findById(userId);
    } else if (role === "subuser") {
      user = await SubUser.findById(userId).populate("adminId"); // Get subuser and populate admin details

      if (user && user.adminId) {
        adminData = await User.findById(user.adminId);
      }
    } else if (role === "super_admin") {
      user = await User.findById(userId);
      return res.json({
        message: "Sufficient credits available",
        vapiPhoneNumberId: user.vapiPhoneNumberId,
      });
    }

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    const availableCredits = user.credits || user.credit;
    if (availableCredits >= callCount) {
      return res.json({
        message: "Sufficient credits available",
        remainingCredits: availableCredits,
        vapiPhoneNumberId:
          user.vapiPhoneNumberId ||
          (adminData ? adminData.vapiPhoneNumberId : null),
      });
    } else {
      return res.status(403).json({
        message: "Insufficient credits for bulk call",
        vapiPhoneNumberId:
          user.vapiPhoneNumberId ||
          (adminData ? adminData.vapiPhoneNumberId : null),
      });
    }
  } catch (error) {
    console.error("Error checking credits for bulk call:", error);
    res.status(500).json({
      message: "An error occurred while checking credits for bulk call",
    });
  }
});

router.get("/admins", async (req, res) => {
  try {
    const admins = await User.find({ role: "admin" });
    res.status(200).json({ admins: admins });
  } catch (error) {
    console.error("Error fetching admin data:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// router.get("/get-graphData", async (req, res) => {
//   try {
//     const days = parseInt(req.query.days, 10) || 15;

//     const currentDate = new Date();
//     const startDate = new Date();
//     startDate.setDate(currentDate.getDate() - days);
//     const formattedStartDate = startDate.toISOString().split("T")[0];
//     const formattedEndDate = currentDate.toISOString().split("T")[0];

//     const response = await axios.get(API_URL, {
//       headers: {
//         Authorization: `Bearer ${VAPI_API_KEY}`,
//       },
//       params: {
//         createdAtGt: formattedStartDate,
//         createdAtLt: formattedEndDate,
//       },
//     });

//     if (response.status === 200) {
//       const callData = response.data;

//       return res.status(200).json({
//         message: "Data sent successfully",
//         success: true,
//         callData: callData.length,
//       });
//     } else {
//       return res.status(response.status).json({
//         message: "Failed to fetch data from VAPI API",
//         success: false,
//       });
//     }
//   } catch (error) {
//     console.error("Error fetching graph data:", error);
//     return res.status(500).json({
//       message: "An error occurred while fetching graph data",
//       success: false,
//     });
//   }
// });

router.post("/updateProfilePic", upload.single("image"), async (req, res) => {
  try {
    const token = req.headers.authorization.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.userId;
    const userRole = decoded.role;

    let updatedUser;
    if (
      userRole === "admin" ||
      userRole === "user" ||
      userRole === "super_admin"
    ) {
      updatedUser = await User.findById(userId);
    } else if (userRole === "subuser") {
      updatedUser = await SubUser.findById(userId);
    }

    if (!updatedUser) {
      return res
        .status(404)
        .json({ status: "error", message: "User or Subuser not found" });
    }

    if (!req.file) {
      return res
        .status(400)
        .json({ status: "error", message: "No file uploaded" });
    }

    updatedUser.profileImage = {
      buffer: req.file.buffer,
      contentType: req.file.mimetype,
      originalName: req.file.originalname,
    };

    await updatedUser.save();
    res.json({ status: "ok", user: updatedUser });
  } catch (error) {
    console.error("Profile Image error: " + error);
    res.status(500).json({ status: "error", message: error.message });
  }
});

router.post("/request-demo", verifyToken, async (req, res) => {
  const { timePeriod } = req.body;
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    if (user.demoCall >= 3) {
      return res.status(403).json({ message: "Demo call limit exceeded" });
    }
    user.demoCall += 1;
    await user.save();
    return res.status(200).json({ message: "Demo requested successfully" });
  } catch (error) {
    console.error("Error requesting demo:", error);
    return res
      .status(500)
      .json({ message: "Server error. Please try again later." });
  }
});

router.post("/config", async (req, res) => {
  try {
    const superAdminUser = await User.findOne({ role: "super_admin" });
    const tokenCall = superAdminUser.tokenCall;
    const client1 = new VapiClient({
      token: tokenCall,
    });
    const token = req.headers.authorization.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.userId;
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const { twilioSid, twilioToken, twilioNum } = req.body;
    user.twilioSid = twilioSid;
    user.twilioToken = twilioToken;
    user.twilioNum = twilioNum;
    await user.save();

    let vapiResponse;
    try {
      // Attempt to create a new phone number in the Vapi API
      vapiResponse = await client1.phoneNumbers.create({
        provider: "twilio",
        number: twilioNum,
        twilioAccountSid: twilioSid,
        twilioAuthToken: twilioToken,
      });
      user.vapiPhoneNumberId = vapiResponse.id;
      user.vapiSipUri = vapiResponse.sipUri;
    } catch (error) {
      // Check if the error is due to an existing phone number
      if (
        error.statusCode === 400 &&
        error.body.message.includes("Existing Phone Number")
      ) {
        // Extract the existing phone number ID from the error message
        const existingPhoneNumberId = error.body.message.match(
          /Existing Phone Number ([\w-]+)/
        )[1];

        // If the phone number already exists, retrieve its details
        const existingPhoneNumber = await client1.phoneNumbers.get(
          existingPhoneNumberId
        );
        user.vapiPhoneNumberId = existingPhoneNumber.id;
        user.vapiSipUri = existingPhoneNumber.sipUri;
      } else {
        // If it's a different error, rethrow it
        throw error;
      }
    }

    await user.save();
    res.status(200).json({
      message: "Configuration saved and Vapi details added successfully!",
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "An error occurred", error });
  }
});

router.get("/get-twilio-data", verifyToken, async (req, res) => {
  try {
    const { userId, role } = req;
    const daysBack = parseInt(req.query.days) || 1;

    let twilioSid, twilioToken;

    if (role === "admin") {
      const adminUser = await User.findById(userId);
      if (!adminUser)
        return res.status(404).json({ message: "Admin not found" });
      twilioSid = adminUser.twilioSid;
      twilioToken = adminUser.twilioToken;
    } else if (role === "subuser") {
      const subUser = await SubUser.findById(userId);
      if (!subUser)
        return res.status(404).json({ message: "Subuser not found" });

      const admin = await User.findById(subUser.adminId);
      if (!admin)
        return res.status(404).json({ message: "Admin for subuser not found" });

      twilioSid = admin.twilioSid;
      twilioToken = admin.twilioToken;
    }

    if (!twilioSid || !twilioToken) {
      return res.status(400).json({ message: "Twilio credentials missing" });
    }

    // Date range for filtering messages
    const today = new Date();
    const startDate = new Date();
    startDate.setDate(today.getDate() - daysBack);

    // Fetch messages from Twilio API
    const twilioResponse = await axios.get(
      `https://api.twilio.com/2010-04-01/Accounts/${twilioSid}/Messages.json`,
      {
        auth: {
          username: twilioSid,
          password: twilioToken,
        },
        params: {
          DateSentAfter: startDate.toISOString().split("T")[0],
          DateSentBefore: today.toISOString().split("T")[0],
          PageSize: 100, // Limit the number of messages per request
        },
      }
    );

    const messages = twilioResponse.data.messages;

    res.status(200).json({
      success: true,
      messages: messages.slice(0, 3), // Return only the last 3 messages
      total: messages.length,
    });
  } catch (error) {
    console.error(`Error fetching Twilio messages: ${error.message}`);
    res.status(500).json({
      success: false,
      message: "Failed to fetch Twilio messages",
    });
  }
});

router.get("/get-call-data", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Authorization token missing" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.userId;

    // Find user or sub-user
    let user = await User.findById(userId);
    if (!user) {
      const subUser = await SubUser.findById(userId);
      if (!subUser) {
        return res.status(404).json({ error: "User not found" });
      }
      user = await User.findById(subUser.adminId);
      if (!user) {
        return res.status(404).json({ error: "Admin user not found" });
      }
    }

    // Ensure Twilio and VAPI configuration exists
    const { twilioNum, twilioSid, twilioToken, vapiPhoneNumberId } = user;
    if (!twilioNum || !twilioSid || !twilioToken || !vapiPhoneNumberId) {
      return res
        .status(404)
        .json({ error: "Configuration missing for this user" });
    }

    // Initialize Twilio Client
    const twilioClient = new twilio(twilioSid, twilioToken);

    // Fetch call data from Twilio
    const twilioCalls = await twilioClient.calls.list({
      limit: 500,
    });
    const sortedCalls = twilioCalls
      .sort(
        (a, b) =>
          new Date(b.startTime || b.createdAt) -
          new Date(a.startTime || a.createdAt)
      )
      .slice(0, 7);

    res.status(200).json({
      totalCalls: twilioCalls.length,
      latestCalls: sortedCalls,
    });
  } catch (error) {
    console.error("Error fetching call logs:", error);
    res.status(500).json({ error: "Error fetching call logs" });
  }
});

router.get("/get-call-data-all", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Authorization token missing" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.userId;

    // Find user or sub-user
    let user = await User.findById(userId);
    if (!user) {
      const subUser = await SubUser.findById(userId);
      if (!subUser) {
        return res.status(404).json({ error: "User not found" });
      }
      user = await User.findById(subUser.adminId);
      if (!user) {
        return res.status(404).json({ error: "Admin user not found" });
      }
    }

    // Ensure Twilio and VAPI configuration exists
    const { twilioNum, twilioSid, twilioToken, vapiPhoneNumberId } = user;
    if (!twilioNum || !twilioSid || !twilioToken || !vapiPhoneNumberId) {
      return res
        .status(404)
        .json({ error: "Configuration missing for this user" });
    }

    // Initialize Twilio Client
    const twilioClient = new twilio(twilioSid, twilioToken);

    // Fetch call data from Twilio
    const twilioCalls = await twilioClient.calls.list({
      limit: 500,
    });

    res.status(200).json({
      latestCalls: twilioCalls,
    });
  } catch (error) {
    console.error("Error fetching call logs:", error);
    res.status(500).json({ error: "Error fetching call logs" });
  }
});

router.post("/transcript", async (req, res) => {
  const superAdminUser = await User.findOne({ role: "super_admin" });
  const tokenCall = superAdminUser.tokenCall;
  const client1 = new VapiClient({
    token: tokenCall,
  });
  const { callSid } = req.body;
  if (!callSid) return res.status(400).json({ error: "Call SID is required" });

  try {
    const vapiResponse = await client1.calls.list();
    const callDetails = vapiResponse.find(
      (call) => call.phoneCallProviderId === callSid
    );
    if (callDetails) {
      res.json({
        transcript: callDetails.transcript || "Transcript not available",
        summary: callDetails.analysis?.summary || "Summary not available",
      });
    } else {
      res.status(404).json({ error: "Call not found" });
    }
  } catch (error) {
    console.error("Error fetching transcript data:", error);
    res.status(500).json({ error: "Failed to fetch transcript" });
  }
});

router.post("/transcript-all", verifyToken, async (req, res) => {
  try {
    let twilioConfig, vapiConfig;
    if (req.role === "subuser") {
      // If user is a subuser, fetch their admin's configuration
      const subUser = await SubUser.findById(req.userId).populate("adminId");
      if (!subUser || !subUser.adminId) {
        return res
          .status(404)
          .json({ error: "Admin configuration not found for subuser" });
      }
      const admin = subUser.adminId;

      twilioConfig = {
        sid: admin.twilioSid,
        token: admin.twilioToken,
        num: admin.twilioNum,
      };
      vapiConfig = admin.vapiPhoneNumberId;
    } else {
      // Fetch config directly from the user if they are not a subuser
      const user = await User.findById(req.userId);
      twilioConfig = {
        sid: user.twilioSid,
        token: user.twilioToken,
        num: user.twilioNum,
      };
      vapiConfig = user.vapiPhoneNumberId;
    }

    // Validate Twilio/VAPI configuration
    if (
      !twilioConfig.sid ||
      !twilioConfig.token ||
      !twilioConfig.num ||
      !vapiConfig
    ) {
      return res
        .status(404)
        .json({ error: "Configuration missing for this user" });
    }

    // Initialize Twilio Client
    const twilioClient = new twilio(twilioConfig.sid, twilioConfig.token);

    // Fetch call data from Twilio
    const twilioCalls = await twilioClient.calls.list({ limit: 500 });

    // Fetch call transcripts from VAPI client (assuming client1 is correctly configured)
    const vapiResponse = await twilioClient.calls.list();
    const transcripts = vapiResponse.map((call) => ({
      name: call.callerName || "Name not available",
      phoneNumber: call.callerPhoneNumber || "Phone number not available",
      transcript: call.transcript || "Transcript not available",
      summary: call.analysis?.summary || "Summary not available",
    }));

    res.status(200).json({ twilioCalls, transcripts });
  } catch (error) {
    console.error("Error fetching call data:", error);
    res.status(500).json({ error: "Error fetching call logs" });
  }
});

router.get("/admin/users", async (req, res) => {
  try {
    const token = req.headers.authorization.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (user.role !== "admin" && user.role !== "super_admin") {
      return res.status(403).json({ message: "Access denied: Admins only" });
    }
    res.status(200).json(user);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "An error occurred", error });
  }
});

router.put("/admin/users", async (req, res) => {
  try {
    const token = req.headers.authorization.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.userId;
    const superAdminUser = await User.findOne({ role: "super_admin" });
    const tokenCall = superAdminUser.tokenCall;
    const client1 = new VapiClient({
      token: tokenCall,
    });
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const { twilioSid, twilioToken, twilioNum } = req.body;
    let credentialsUpdated = false;

    if (
      user.twilioSid !== twilioSid ||
      user.twilioToken !== twilioToken ||
      user.twilioNum !== twilioNum
    ) {
      user.twilioSid = twilioSid;
      user.twilioToken = twilioToken;
      user.twilioNum = twilioNum;
      credentialsUpdated = true;
    }

    if (credentialsUpdated) {
      let vapiResponse;
      try {
        vapiResponse = await client1.phoneNumbers.create({
          provider: "twilio",
          number: twilioNum,
          twilioAccountSid: twilioSid,
          twilioAuthToken: twilioToken,
        });

        user.vapiPhoneNumberId = vapiResponse.id;
        user.vapiSipUri = vapiResponse.sipUri;
      } catch (error) {
        // Specific handling for invalid phone number format
        if (
          error.statusCode === 400 &&
          error.body.message.includes("number must be a valid phone number")
        ) {
          return res.status(400).json({
            message:
              "Invalid phone number format. Please enter the phone number in E.164 format (e.g., +1xxxxxxxxxx).",
          });
        } else if (
          error.statusCode === 400 &&
          error.body.message.includes("Existing Phone Number")
        ) {
          const existingPhoneNumberId = error.body.message.match(
            /Existing Phone Number ([\w-]+)/
          )[1];

          const existingPhoneNumber = await client1.phoneNumbers.get(
            existingPhoneNumberId
          );
          user.vapiPhoneNumberId = existingPhoneNumber.id;
          user.vapiSipUri = existingPhoneNumber.sipUri;
        } else {
          throw error;
        }
      }

      await user.save();
      return res.status(200).json({
        message: "Configuration saved and Vapi details added successfully!",
      });
    } else {
      await user.save();
      return res.status(200).json({
        message: "Configuration saved successfully!",
      });
    }
  } catch (error) {
    console.error("An error occurred:", error);
    res.status(500).json({ message: "An error occurred", error });
  }
});

const clientmail = require("@sendgrid/client");
clientmail.setDefaultRequest("qs", { limit: 5, offset: 15 });

router.get("/get-mail-data", verifyToken, async (req, res) => {
  const { userId, role } = req;
  const days = parseInt(req.query.days) || 15; // Default to 15 days if no value provided

  try {
    let adminUser;

    if (role === "admin") {
      adminUser = await User.findById(userId);
      if (!adminUser)
        return res.status(404).json({ message: "Admin user not found" });
    } else if (role === "subuser") {
      const subUser = await SubUser.findById(userId);
      if (!subUser)
        return res.status(404).json({ message: "Sub-user not found" });
      adminUser = await User.findById(subUser.adminId);
      if (!adminUser)
        return res.status(404).json({ message: "Admin user not found" });
    } else {
      return res.status(403).json({ message: "Unauthorized access" });
    }

    // Calculate the date based on the dynamic days value
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    // Filter mainCount to get entries within the specified range
    const recentEmailData = adminUser.mainCount.filter(
      (entry) => entry.date >= startDate
    );

    res.status(200).json({ emailData: recentEmailData });
  } catch (error) {
    console.error("Failed to retrieve mail data:", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

async function testSendGridApiKey(apiKey) {
  if (!apiKey || typeof apiKey !== "string" || apiKey.trim() === "") {
    return null;
  }

  const sendGridApiUrl = `https://api.sendgrid.com/v3/user/account`;

  try {
    const response = await axios.get(sendGridApiUrl, {
      headers: {
        Authorization: `Bearer ${apiKey.trim()}`,
      },
    });

    clientmail.setApiKey(apiKey);
    const request = {
      url: "/v3/mail_settings",
      method: "GET",
    };

    // Fetch mail settings
    const [mailResponse, mailBody] = await clientmail.request(request);

    return {
      accountData: response.data,
      mailSettings: mailBody,
    };
  } catch (error) {
    console.error(
      "Authorization test failed:",
      error.message,
      error.response?.data
    );

    if (error.response?.status === 403) {
      console.error(
        "Access forbidden: Verify that your API key has Full Access permissions in SendGrid."
      );
    } else if (error.response?.status === 401) {
      console.error(
        "Unauthorized: The API key may be incorrect, inactive, or expired."
      );
    }
    return null;
  }
}

router.delete("/admin/users/:id", async (req, res) => {
  try {
    const { id } = req.params;
    await User.findByIdAndUpdate(id, {
      $unset: {
        twilioSid: "",
        twilioToken: "",
        twilioNum: "",
        vapiPhoneNumberId: "",
        vapiSipUri: "",
      },
    });

    res.status(200).json({ message: "Specified fields removed successfully" });
  } catch (error) {
    console.error("Error removing specified fields:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

router.post("/config-mail", async (req, res) => {
  try {
    // Extract the token from the Authorization header
    const token = req.headers.authorization.split(" ")[1];
    if (!token)
      return res.status(403).json({ message: "Authorization token required" });

    // Verify and decode the token
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.userId; // Ensure 'userId' was included in your token payload

    // Fetch the user by ID
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Extract SendGrid details from request body
    const { sendGridEmail, sendGridApiKey } = req.body;

    // Update user's SendGrid configuration
    user.sendGridEmail = sendGridEmail;
    user.sendGridApiKey = sendGridApiKey;

    // Save the updated user data
    await user.save();

    return res
      .status(200)
      .json({ message: "Configuration added successfully!" });
  } catch (error) {
    console.error("Error in config-mail route:", error);
    return res
      .status(500)
      .json({ message: "An error occurred while adding configuration", error });
  }
});

// Route to delete specific fields (sendGridApiKey and sendGridEmail) for a user by ID
router.delete("/admin/sendgrid/:userId", verifyToken, async (req, res) => {
  const { userId } = req.params;

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    // Use MongoDB $unset operator to remove the specific fields
    await User.findByIdAndUpdate(userId, {
      $unset: {
        sendGridApiKey: "",
        sendGridEmail: "",
      },
    });

    return res
      .status(200)
      .json({ message: "SendGrid configuration removed successfully" });
  } catch (error) {
    console.error("Error deleting SendGrid configuration:", error);
    return res.status(500).json({
      message: "An error occurred while deleting SendGrid configuration",
      error,
    });
  }
});

// Route to update SendGrid email and API key for a user by ID
router.put("/admin/sendgrid/update/:userId", verifyToken, async (req, res) => {
  const { userId } = req.params;
  const { sendGridEmail, sendGridApiKey } = req.body;

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    user.sendGridEmail = sendGridEmail || user.sendGridEmail;
    user.sendGridApiKey = sendGridApiKey || user.sendGridApiKey;

    await user.save();

    return res
      .status(200)
      .json({ message: "SendGrid configuration updated successfully" });
  } catch (error) {
    console.error("Error updating SendGrid configuration:", error);
    return res.status(500).json({
      message: "An error occurred while updating SendGrid configuration",
      error,
    });
  }
});

const path = require("path");
router.get("/download-call", (req, res) => {
  const filePath = path.join(__dirname, "../sample/bulk-call-server.xlsx"); // Path to your sample file
  res.download(filePath, "sample-call.xlsx", (err) => {
    if (err) {
      console.error("Error downloading file:", err);
      res.status(500).send("Error downloading file");
    }
  });
});
router.get("/download-sms", (req, res) => {
  const filePath = path.join(__dirname, "../sample/ai-sample-file.xlsx"); // Path to your sample file
  res.download(filePath, "sample-sms.xlsx", (err) => {
    if (err) {
      console.error("Error downloading file:", err);
      res.status(500).send("Error downloading file");
    }
  });
});
router.get("/download-mail", (req, res) => {
  const filePath = path.join(__dirname, "../sample/demo_mail-server.xlsx");
  res.download(filePath, "sample-mail.xlsx", (err) => {
    if (err) {
      console.error("Error downloading file:", err);
      res.status(500).send("Error downloading file");
    }
  });
});

router.get("/admin/users-callToken", async (req, res) => {
  const token = req.headers.authorization.split(" ")[1];
  const decoded = jwt.verify(token, JWT_SECRET);
  const user = await User.findById(decoded.userId);
  if (user.role === "super_admin") {
    return res.status(201).json({ message: "Data", data: user.tokenCall });
  }
  return res.status(403).json({ message: "Access denied" });
});

const fs = require("fs");

const updateEnvFile = (tokenCall) => {
  // Adjust path as needed based on your folder structure
  const envFilePath = path.join(__dirname, "../../client/dist/env.js");
  if (!fs.existsSync(path.dirname(envFilePath))) {
    console.error("Directory does not exist:", path.dirname(envFilePath));
    return;
  }

  const content = ` const url = " // http://localhost:3000";
const url = "https://aienagage.onrender.com";
const callToken = "${tokenCall}";`;

  // Write the content to the env.js file
  fs.writeFileSync(envFilePath, content, "utf8", (err) => {
    if (err) {
      console.error("Error writing to env.js:", err);
    } else {
      console.log("env.js file updated successfully!");
    }
  });
};

router.put("/admin/callToken/update", async (req, res) => {
  const token = req.headers.authorization.split(" ")[1];
  const decoded = jwt.verify(token, JWT_SECRET);
  const user = await User.findById(decoded.userId);
  if (user.role === "super_admin") {
    const dat = await User.findByIdAndUpdate(user._id, {
      tokenCall: req.body.sendGridEmail,
    });
    updateEnvFile(req.body.sendGridEmail);
    return res.status(201).json({ message: "Data Updated" });
  }
  return res.status(403).json({ message: "Access denied" });
});

router.delete("/admin/vapi-delete", async (req, res) => {
  try {
    const token = req.headers.authorization.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.role === "super_admin") {
      // Set the tokenCall field to an empty string
      await User.findByIdAndUpdate(user._id, { tokenCall: "" });
      updateEnvFile("");
      return res.status(200).json({ message: "Field cleared successfully" });
    }

    return res.status(403).json({ message: "Access denied" });
  } catch (error) {
    console.error("Error in delete route:", error);
    return res.status(500).json({ message: "Internal Server Error", error });
  }
});

router.post("/config-call", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res
        .status(401)
        .json({ message: "Authorization header missing or invalid" });
    }

    // Extract the token
    const token = authHeader.split(" ")[1];

    // Verify the token
    const decoded = jwt.verify(token, JWT_SECRET);

    // Find the user based on the decoded userId
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Check for super_admin role
    if (user.role !== "super_admin") {
      return res.status(403).json({ message: "Access denied" });
    }

    // Update the user's callToken
    if (!req.body.tokenCall) {
      return res
        .status(400)
        .json({ message: "Missing tokenCall in request body" });
    }

    await User.findByIdAndUpdate(user._id, { tokenCall: req.body.tokenCall });
    updateEnvFile(req.body.tokenCall);
    return res.status(201).json({ message: "Data Updated" });
  } catch (error) {
    console.error("Error in /config-call route:", error);

    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ message: "Invalid token" });
    }

    res.status(500).json({ message: "Internal server error" });
  }
});

router.get("/home", authMiddleware, (req, res) => {
  res.flash("Welcome to home page");
  res.status(200).json({
    message: "Welcome to the home page!",
    user: req.user,
  });
});

module.exports = router;
