import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { pool } from "./db.js";

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "your-super-secret-jwt-key-change-in-production";
const PORT = process.env.PORT || 5000;

// Test DB connection
pool.query("SELECT NOW()", (err, res) => {
  if (err) {
    console.error("❌ Database connection failed:", err);
  } else {
    console.log("✅ Database connected successfully");
  }
});

// ============================================
// HELPER FUNCTIONS
// ============================================

// Convert GPS coordinates to pincode using reverse geocoding
const getPincodeFromCoordinates = async (latitude, longitude) => {
  try {
    const response = await fetch(
      `https://nominatim.openstreetmap.org/reverse?lat=${latitude}&lon=${longitude}&format=json&addressdetails=1`,
      {
        headers: {
          'User-Agent': 'ClientTrackingApp/1.0'
        }
      }
    );
    
    const data = await response.json();
    const pincode = data.address?.postcode || null;
    
    console.log(`📍 Coordinates (${latitude}, ${longitude}) → Pincode: ${pincode}`);
    return pincode;
  } catch (error) {
    console.error("❌ Reverse geocoding error:", error);
    return null;
  }
};

// Get user's current pincode from their latest location log
const getUserCurrentPincode = async (userId) => {
  try {
    const result = await pool.query(
      `SELECT pincode FROM location_logs 
       WHERE user_id = $1 AND pincode IS NOT NULL
       ORDER BY timestamp DESC 
       LIMIT 1`,
      [userId]
    );

    if (result.rows.length === 0) {
      console.log(`⚠️ No location log found for user ${userId}`);
      return null;
    }

    const pincode = result.rows[0].pincode;
    console.log(`✅ User ${userId} current pincode: ${pincode}`);
    return pincode;
  } catch (error) {
    console.error("❌ Error getting user pincode:", error);
    return null;
  }
};

// ============================================
// MIDDLEWARE
// ============================================

// Verify JWT Token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "AccessTokenRequired" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "InvalidToken" });
    }
    req.user = user;
    next();
  });
};

// ============================================
// AUTH ROUTES
// ============================================

// SIGNUP
app.post("/auth/signup", async (req, res) => {
  const client = await pool.connect();
  try {
    const { email, password, fullName, department, workHoursStart, workHoursEnd } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "MissingFields" });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: "PasswordTooShort" });
    }

    const userExists = await client.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );

    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: "UserExists" });
    }

    await client.query("BEGIN");

    const hashedPassword = await bcrypt.hash(password, 10);

    const userResult = await client.query(
      "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email, created_at",
      [email, hashedPassword]
    );

    const user = userResult.rows[0];

    const profileResult = await client.query(
      `INSERT INTO profiles (user_id, email, full_name, department, work_hours_start, work_hours_end) 
       VALUES ($1, $2, $3, $4, $5, $6) 
       RETURNING id, user_id, email, full_name, department, work_hours_start, work_hours_end`,
      [user.id, email, fullName || null, department || null, workHoursStart || null, workHoursEnd || null]
    );

    const profile = profileResult.rows[0];

    await client.query("COMMIT");

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "7d",
    });

    res.status(201).json({
      message: "SignupSuccess",
      token,
      user: {
        id: user.id,
        email: user.email,
        profile: profile,
        createdAt: user.created_at,
      },
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("SIGNUP ERROR:", err);
    res.status(500).json({ error: "SignupFailed" });
  } finally {
    client.release();
  }
});

// LOGIN
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "MissingFields" });
    }

    const result = await pool.query(
      `SELECT u.*, p.full_name, p.department, p.work_hours_start, p.work_hours_end
       FROM users u
       LEFT JOIN profiles p ON u.id = p.user_id
       WHERE u.email = $1`,
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "InvalidCredentials" });
    }

    const user = result.rows[0];

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: "InvalidCredentials" });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "7d",
    });

    res.json({
      message: "LoginSuccess",
      token,
      user: {
        id: user.id,
        email: user.email,
        fullName: user.full_name,
        department: user.department,
        workHoursStart: user.work_hours_start,
        workHoursEnd: user.work_hours_end,
      },
    });
  } catch (err) {
    console.error("LOGIN ERROR:", err);
    res.status(500).json({ error: "LoginFailed" });
  }
});

// FORGOT PASSWORD
app.post("/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: "EmailRequired" });
    }

    const result = await pool.query("SELECT id FROM users WHERE email = $1", [email]);

    if (result.rows.length === 0) {
      return res.json({ message: "PasswordResetEmailSent" });
    }

    const resetToken = crypto.randomBytes(32).toString("hex");
    const resetTokenExpiry = new Date(Date.now() + 3600000); // 1 hour

    await pool.query(
      "UPDATE users SET reset_token = $1, reset_token_expiry = $2 WHERE email = $3",
      [resetToken, resetTokenExpiry, email]
    );

    console.log("🔑 Password Reset Token:", resetToken);
    console.log("📧 For Email:", email);

    res.json({
      message: "PasswordResetEmailSent",
      resetToken: resetToken, // Remove in production
    });
  } catch (err) {
    console.error("FORGOT PASSWORD ERROR:", err);
    res.status(500).json({ error: "ForgotPasswordFailed" });
  }
});

// RESET PASSWORD
app.post("/auth/reset-password", async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({ error: "MissingFields" });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ error: "PasswordTooShort" });
    }

    const result = await pool.query(
      "SELECT id FROM users WHERE reset_token = $1 AND reset_token_expiry > NOW()",
      [token]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: "InvalidOrExpiredToken" });
    }

    const userId = result.rows[0].id;
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await pool.query(
      "UPDATE users SET password = $1, reset_token = NULL, reset_token_expiry = NULL WHERE id = $2",
      [hashedPassword, userId]
    );

    res.json({ message: "PasswordResetSuccess" });
  } catch (err) {
    console.error("RESET PASSWORD ERROR:", err);
    res.status(500).json({ error: "ResetPasswordFailed" });
  }
});

// GET PROFILE
app.get("/auth/profile", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.email, p.full_name, p.department, p.work_hours_start, p.work_hours_end, p.created_at
       FROM users u
       LEFT JOIN profiles p ON u.id = p.user_id
       WHERE u.id = $1`,
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "UserNotFound" });
    }

    res.json({ user: result.rows[0] });
  } catch (err) {
    console.error("GET PROFILE ERROR:", err);
    res.status(500).json({ error: "GetProfileFailed" });
  }
});

// UPDATE PROFILE
app.put("/auth/profile", authenticateToken, async (req, res) => {
  try {
    const { fullName, department, workHoursStart, workHoursEnd } = req.body;

    const result = await pool.query(
      `UPDATE profiles 
       SET full_name = $1, department = $2, work_hours_start = $3, work_hours_end = $4
       WHERE user_id = $5
       RETURNING id, user_id, email, full_name, department, work_hours_start, work_hours_end`,
      [fullName, department, workHoursStart, workHoursEnd, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "ProfileNotFound" });
    }

    res.json({
      message: "ProfileUpdated",
      profile: result.rows[0],
    });
  } catch (err) {
    console.error("UPDATE PROFILE ERROR:", err);
    res.status(500).json({ error: "UpdateProfileFailed" });
  }
});

// ============================================
// CLIENTS ROUTES (WITH PINCODE FILTERING)
// ============================================

// CREATE CLIENT (with pincode auto-calculation)
app.post("/clients", authenticateToken, async (req, res) => {
  try {
    const { name, email, phone, address, latitude, longitude, status, notes } = req.body;

    if (!name) {
      return res.status(400).json({ error: "ClientNameRequired" });
    }

    // Auto-calculate pincode if lat/lng provided
    let pincode = null;
    if (latitude && longitude) {
      pincode = await getPincodeFromCoordinates(latitude, longitude);
    }

    const result = await pool.query(
      `INSERT INTO clients (name, email, phone, address, latitude, longitude, status, notes, pincode, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       RETURNING *`,
      [name, email || null, phone || null, address || null, latitude || null, longitude || null, status || "active", notes || null, pincode, req.user.id]
    );

    console.log(`✅ Client created: ${name} (Pincode: ${pincode || 'N/A'})`);

    res.status(201).json({
      message: "ClientCreated",
      client: result.rows[0],
    });
  } catch (err) {
    console.error("CREATE CLIENT ERROR:", err);
    res.status(500).json({ error: "CreateClientFailed" });
  }
});

// GET ALL CLIENTS (FILTERED BY USER'S CURRENT PINCODE)
app.get("/clients", authenticateToken, async (req, res) => {
  try {
    const { status, search, page = 1, limit = 100 } = req.query;
    const offset = (page - 1) * limit;

    console.log(`🔍 Fetching clients for user: ${req.user.id}`);

    // Get user's current pincode from their latest location log
    const userPincode = await getUserCurrentPincode(req.user.id);

    if (!userPincode) {
      return res.status(400).json({ 
        error: "NoPincodeFound",
        message: "Please enable location tracking first. No location data available."
      });
    }

    console.log(`📍 Filtering clients by pincode: ${userPincode}`);

    // Build query - FILTER BY PINCODE
    let query = "SELECT * FROM clients WHERE pincode = $1";
    const params = [userPincode];
    let paramCount = 1;

    // Additional filters
    if (status) {
      paramCount++;
      query += ` AND status = $${paramCount}`;
      params.push(status);
    }

    if (search) {
      paramCount++;
      query += ` AND (name ILIKE $${paramCount} OR email ILIKE $${paramCount} OR phone ILIKE $${paramCount})`;
      params.push(`%${search}%`);
    }

    query += ` ORDER BY created_at DESC LIMIT $${paramCount + 1} OFFSET $${paramCount + 2}`;
    params.push(limit, offset);

    const result = await pool.query(query, params);

    // Get total count
    let countQuery = "SELECT COUNT(*) FROM clients WHERE pincode = $1";
    const countParams = [userPincode];
    let countParamIndex = 1;

    if (status) {
      countParamIndex++;
      countQuery += ` AND status = $${countParamIndex}`;
      countParams.push(status);
    }

    const countResult = await pool.query(countQuery, countParams);
    const total = parseInt(countResult.rows[0].count);

    console.log(`✅ Found ${result.rows.length} clients in pincode ${userPincode}`);

    res.json({
      clients: result.rows,
      userPincode: userPincode,
      filteredByPincode: true,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: total,
        totalPages: Math.ceil(total / limit),
      },
    });
  } catch (err) {
    console.error("GET CLIENTS ERROR:", err);
    res.status(500).json({ error: "GetClientsFailed" });
  }
});

// GET SINGLE CLIENT
app.get("/clients/:id", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM clients WHERE id = $1",
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "ClientNotFound" });
    }

    res.json({ client: result.rows[0] });
  } catch (err) {
    console.error("GET CLIENT ERROR:", err);
    res.status(500).json({ error: "GetClientFailed" });
  }
});

// UPDATE CLIENT
app.put("/clients/:id", authenticateToken, async (req, res) => {
  try {
    const { name, email, phone, address, latitude, longitude, status, notes } = req.body;

    // Auto-calculate pincode if lat/lng changed
    let pincode = null;
    if (latitude && longitude) {
      pincode = await getPincodeFromCoordinates(latitude, longitude);
    }

    const result = await pool.query(
      `UPDATE clients 
       SET name = $1, email = $2, phone = $3, address = $4, latitude = $5, longitude = $6, status = $7, notes = $8, pincode = $9
       WHERE id = $10
       RETURNING *`,
      [name, email, phone, address, latitude, longitude, status, notes, pincode, req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "ClientNotFound" });
    }

    res.json({
      message: "ClientUpdated",
      client: result.rows[0],
    });
  } catch (err) {
    console.error("UPDATE CLIENT ERROR:", err);
    res.status(500).json({ error: "UpdateClientFailed" });
  }
});

// DELETE CLIENT
app.delete("/clients/:id", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "DELETE FROM clients WHERE id = $1 RETURNING id",
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "ClientNotFound" });
    }

    res.json({ message: "ClientDeleted" });
  } catch (err) {
    console.error("DELETE CLIENT ERROR:", err);
    res.status(500).json({ error: "DeleteClientFailed" });
  }
});

// ============================================
// LOCATION LOGS ROUTES
// ============================================

// CREATE LOCATION LOG (with automatic pincode detection)
app.post("/location-logs", authenticateToken, async (req, res) => {
  try {
    const { latitude, longitude, accuracy, activity, notes } = req.body;

    if (!latitude || !longitude) {
      return res.status(400).json({ error: "LocationRequired" });
    }

    console.log(`📍 Logging location for user ${req.user.id}: ${latitude}, ${longitude}`);

    // Get pincode from coordinates
    const pincode = await getPincodeFromCoordinates(latitude, longitude);

    const result = await pool.query(
      `INSERT INTO location_logs (user_id, latitude, longitude, accuracy, activity, notes, pincode)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [req.user.id, latitude, longitude, accuracy || null, activity || null, notes || null, pincode]
    );

    const log = result.rows[0];
    const mappedLog = {
      id: log.id,
      userId: log.user_id,
      latitude: log.latitude,
      longitude: log.longitude,
      accuracy: log.accuracy,
      activity: log.activity,
      notes: log.notes,
      pincode: log.pincode,
      timestamp: log.timestamp
    };

    console.log(`✅ Location logged with pincode: ${pincode}`);

    res.status(201).json({
      message: "LocationLogged",
      log: mappedLog
    });
  } catch (err) {
    console.error("CREATE LOCATION LOG ERROR:", err);
    res.status(500).json({ error: "CreateLocationLogFailed" });
  }
});

// GET LOCATION LOGS
app.get("/location-logs", authenticateToken, async (req, res) => {
  try {
    const { startDate, endDate, page = 1, limit = 50 } = req.query;
    const offset = (page - 1) * limit;

    let query = "SELECT * FROM location_logs WHERE user_id = $1";
    const params = [req.user.id];
    let paramCount = 1;

    if (startDate) {
      paramCount++;
      query += ` AND timestamp >= $${paramCount}`;
      params.push(startDate);
    }

    if (endDate) {
      paramCount++;
      query += ` AND timestamp <= $${paramCount}`;
      params.push(endDate);
    }

    query += ` ORDER BY timestamp DESC LIMIT $${paramCount + 1} OFFSET $${paramCount + 2}`;
    params.push(limit, offset);

    const result = await pool.query(query, params);

    const mappedLogs = result.rows.map(log => ({
      id: log.id,
      userId: log.user_id,
      latitude: log.latitude,
      longitude: log.longitude,
      accuracy: log.accuracy,
      activity: log.activity,
      notes: log.notes,
      pincode: log.pincode,
      timestamp: log.timestamp
    }));

    res.json({
      logs: mappedLogs,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
      },
    });
  } catch (err) {
    console.error("GET LOCATION LOGS ERROR:", err);
    res.status(500).json({ error: "GetLocationLogsFailed" });
  }
});

// ============================================
// UTILITY ROUTES
// ============================================

app.get("/", (req, res) => {
  res.json({ message: "Client Tracking API with Pincode Filtering" });
});

app.get("/dbtest", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json({ db_time: result.rows[0].now });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📍 Pincode-based filtering enabled`);
});