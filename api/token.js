
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

module.exports = function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const privateKey = process.env.WEBENGAGE_PRIVATE_KEY;
  const expectedSecret = process.env.TEST_LOGIN_SECRET;

  if (!privateKey || !expectedSecret) {
    return res.status(500).json({
      error: "Server authentication configuration is incomplete"
    });
  }

  const body = req.body || {};
  const cuid = typeof body.cuid === "string" ? body.cuid.trim() : "";
  const suppliedSecret =
    typeof body.testSecret === "string" ? body.testSecret : "";

  if (!cuid || cuid.length > 200) {
    return res.status(400).json({ error: "Enter a valid CUID" });
  }

  const expected = Buffer.from(expectedSecret);
  const supplied = Buffer.from(suppliedSecret);

  if (
    expected.length !== supplied.length ||
    !crypto.timingSafeEqual(expected, supplied)
  ) {
    return res.status(401).json({ error: "Invalid test secret" });
  }

  try {
    const token = jwt.sign(
      { cuid },
      privateKey.replace(/\\n/g, "\n"),
      {
        algorithm: "RS256",
        expiresIn: "15m",
        header: { typ: "JWT" }
      }
    );

    return res.status(200).json({ token, cuid });
  } catch (error) {
    console.error("JWT signing failed:", error.message);
    return res.status(500).json({ error: "JWT generation failed" });
  }
};
