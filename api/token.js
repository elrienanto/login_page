
const jwt = require("jsonwebtoken");

module.exports = function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const privateKey = process.env.WEBENGAGE_PRIVATE_KEY;

  if (!privateKey) {
    return res.status(500).json({
      error: "WEBENGAGE_PRIVATE_KEY is not configured"
    });
  }

  try {
    const token = jwt.sign(
      { cuid: "reo@mailer.com" },
      privateKey.replace(/\\n/g, "\n"),
      {
        algorithm: "RS256",
        expiresIn: "15m",
        header: { typ: "JWT" }
      }
    );

    return res.status(200).json({
      token,
      cuid: "reo@mailer.com"
    });
  } catch (error) {
    console.error("JWT signing failed:", error.message);
    return res.status(500).json({
      error: "JWT generation failed"
    });
  }
};
