const {
  STRIPE_PUBLISHABLE_KEY,
  STRIPE_SECRET_KEY,
  EMAIL_USER,
  EMAIL_PASSWORD,
  SENDGRID_API_KEY, 
} = process.env;

const stripe = require("stripe")(STRIPE_SECRET_KEY);
const express = require("express");
const cron = require("node-cron");
const nodemailer = require("nodemailer");
const User = require("../models/userModal");
const transactionSchema = require("../models/transactionSchema");
const router = express.Router();
const sgMail = require("@sendgrid/mail");
sgMail.setApiKey(SENDGRID_API_KEY); 

const sendEmailWithRetry = async (msg, retries = 3) => {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      await sgMail.send(msg);
      return;
    } catch (error) {
      console.error(`Attempt ${attempt} - Failed to send email to ${msg.to}:`, error.response ? error.response.body : error.message);
      if (attempt === retries) throw error; 
    }
  }
};

// Send email function
const sendEmail = async (to, subject, { plan, amount, customMessage }) => {
  const emailHtml = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <style>
        body { font-family: Arial, sans-serif; color: #333; background-color: #f4f4f9; margin: 0; padding: 0; }
        .container { max-width: 600px; margin: 20px auto; background: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
        h1 { color: #4CAF50; }
        p { line-height: 1.6; }
        .details { background: #f9f9f9; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .cta { display: block; text-align: center; color: white; background-color: #4CAF50; padding: 12px; border-radius: 5px; text-decoration: none; font-weight: bold; margin: 20px 0; }
        .footer { font-size: 0.85em; color: #888; text-align: center; margin-top: 20px; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>${subject}</h1>
        <p>Dear Customer,</p>
        <p>${customMessage || 'Thank you for your payment!'}</p>
        <div class="details">
          <p><strong>Subscription Plan:</strong> ${plan}</p>
          <p><strong>Amount:</strong> ${amount} credits</p>
        </div>
        <a class="cta" href="https://www.aiengage.ai/login.html">Go To Login</a>


     
        <div class="footer">
          <p>If you have any questions, feel free to contact us at support@yourwebsite.com.</p>
        </div>
      </div>
    </body>
    </html>
  `;

  const msg = {
    to,
    from: `"AI Calling Service" <choudhardiv@gmail.com>`, 
    subject,
    html: emailHtml,
  };

  await sendEmailWithRetry(msg);

};

// Route for manual payment
router.post("/payment", async (req, res) => {
  try {
    const { userEmail, plan, amount, currency } = req.body;

    if (!userEmail || !plan || !amount || !currency) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    const conversionRates = {
      USD: 1,
      INR: 75,
      EUR: 0.9,
      GBP: 0.75,
      JPY: 110,
      AUD: 1.3,
    };
    const convertedAmount = amount * conversionRates[currency];

    const product = await stripe.products.create({
      name: `${plan} Membership`,
    });

    const price = await stripe.prices.create({
      product: product.id,
      unit_amount: parseInt(convertedAmount * 100),
      currency: currency.toLowerCase(),
      recurring: { interval: "month", interval_count: 1 },
    });

    const session = await stripe.checkout.sessions.create({
      line_items: [
        {
          price: price.id,
          quantity: 1,
        },
      ],
      mode: "subscription",
      success_url: `https://aienagage.onrender.com/api/auth/success/${userEmail}/${plan}/${amount}`,

      //success_url: `http://localhost:3000/api/auth/success/${userEmail}/${plan}/${amount}`,
    
      cancel_url: "https://aienagage.onrender.com/api/auth/failed",   

      //cancel_url: "http://localhost:3000/api/auth/failed",      

      customer_email: userEmail,
    });

    res.json({ url: session.url });
  } catch (error) {
    console.error("Error creating payment session:", error.message);
    res.status(500).send("Error creating payment session.");
  }
});


// Route for successful payment
router.get("/success/:email/:payment/:amount", async (req, res) => {
  try {
    const { email, payment, amount } = req.params;

    let credit=0;
    if(payment === "Platinum")
    {
      credit=6000;
    }else if(payment==="Gold")
    {
      credit=2500;
    }else if(payment === "Silver"){
      credit=1200; 
    }


    console.log("p"+ payment , "a" +amount);
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).send({ message: "User doesn't exist", success: false });
    }
    user.role = "admin";
    user.credits += parseInt(credit, 10);

    const newTransaction = await transactionSchema.create({
      userId: user._id,
      transactionType: "credit",
      amount: payment,
      date: new Date(),
    });

    user.transactions.push(newTransaction._id);
    user.lastPlan = { plan: payment, amount: amount };
    await user.save();

    await sendEmail(email, "Payment Successful from Mazer", {
      plan: payment,
      amount: amount,
    });

    res.redirect("https://www.aiengage.ai/paymentSuccess.html");

   // res.redirect("http://127.0.0.1:5501/client/dist/paymentSuccess.html");
  } catch (err) {
    console.log("Success Error:", err.message);
    return res.status(500).send({ message: "An error occurred during the process", success: false });
  }
});


// Route for failed payment
router.get("/failed", (req, res) => {
  res.redirect("hhttps://www.aiengage.ai/paymentFailed.html");
});

// Schedule cron job for monthly subscription renewal
cron.schedule("0 0 * * *", async () => {

  try {
    const users = await User.find({ "lastPlan.plan": { $exists: true } });

    for (const user of users) {
      const { plan, amount } = user.lastPlan;

      const session = await stripe.checkout.sessions.create({
        payment_method_types: ["card"],
        line_items: [
          {
            name: `${plan} Membership`,
            amount: amount * 100,
            currency: "usd",
            quantity: 1,
          },
        ],
        mode: "payment",
        customer_email: user.email,
        success_url: `https://aienagage.onrender.com/api/auth/success/${user.email}/${plan}/${amount}`,
        cancel_url: "https://aienagage.onrender.com/api/auth/failed",
      });

      await sendEmail(user.email, "Subscription Renewal", {
        plan,
        amount,
        customMessage: "Your subscription has been successfully renewed.",
      });
      console.log(`Renewal email sent to ${user.email}`);
    }
  } catch (error) {
    console.error("Error with monthly subscription:", error.message);
  }
});

module.exports = router;
