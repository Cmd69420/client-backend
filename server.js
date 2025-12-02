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

    // Validation
    if (!email || !password) {
      return res.status(400).json({ error: "MissingFields" });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: "PasswordTooShort" });
    }

    // Check if user exists
    const userExists = await client.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );

    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: "UserExists" });
    }

    // Start transaction
    await client.query("BEGIN");

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user
    const userResult = await client.query(
      "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email, created_at",
      [email, hashedPassword]
    );

    const user = userResult.rows[0];

    // Create profile
    const profileResult = await client.query(
      `INSERT INTO profiles (user_id, email, full_name, department, work_hours_start, work_hours_end) 
       VALUES ($1, $2, $3, $4, $5, $6) 
       RETURNING id, user_id, email, full_name, department, work_hours_start, work_hours_end`,
      [user.id, email, fullName || null, department || null, workHoursStart || null, workHoursEnd || null]
    );

    const profile = profileResult.rows[0];

    // Commit transaction
    await client.query("COMMIT");

    // Generate JWT
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

    // Get user with profile
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

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: "InvalidCredentials" });
    }

    // Generate JWT
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
      // Don't reveal if email exists
      return res.json({ message: "PasswordResetEmailSent" });
    }

    // Generate reset token
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
      // ONLY FOR TESTING - Remove in production!
      resetToken: resetToken,
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

    // Find user with valid token
    const result = await pool.query(
      "SELECT id FROM users WHERE reset_token = $1 AND reset_token_expiry > NOW()",
      [token]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: "InvalidOrExpiredToken" });
    }

    const userId = result.rows[0].id;

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update password and clear token
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

// GET PROFILE (Protected)
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

// UPDATE PROFILE (Protected)
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
// CLIENTS ROUTES
// ============================================

// CREATE CLIENT
app.post("/clients", authenticateToken, async (req, res) => {
  try {
    const { name, email, phone, address, latitude, longitude, status, notes } = req.body;

    if (!name) {
      return res.status(400).json({ error: "ClientNameRequired" });
    }

    const result = await pool.query(
      `INSERT INTO clients (name, email, phone, address, latitude, longitude, status, notes, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING *`,
      [name, email || null, phone || null, address || null, latitude || null, longitude || null, status || "active", notes || null, req.user.id]
    );

    res.status(201).json({
      message: "ClientCreated",
      client: result.rows[0],
    });
  } catch (err) {
    console.error("CREATE CLIENT ERROR:", err);
    res.status(500).json({ error: "CreateClientFailed" });
  }
});

// GET ALL CLIENTS (with pagination and filtering)
app.get("/clients", authenticateToken, async (req, res) => {
  try {
    const { status, search, page = 1, limit =  100 } = req.query;
    const offset = (page - 1) * limit;

    let query = "SELECT * FROM clients WHERE created_by = $1";
    const params = [req.user.id];
    let paramCount = 1;

    // Filter by status
    if (status) {
      paramCount++;
      query += ` AND status = $${paramCount}`;
      params.push(status);
    }

    // Search by name, email, or phone
    if (search) {
      paramCount++;
      query += ` AND (name ILIKE $${paramCount} OR email ILIKE $${paramCount} OR phone ILIKE $${paramCount})`;
      params.push(`%${search}%`);
    }

    query += ` ORDER BY created_at DESC LIMIT $${paramCount + 1} OFFSET $${paramCount + 2}`;
    params.push(limit, offset);

    const result = await pool.query(query, params);

    // Get total count
    let countQuery = "SELECT COUNT(*) FROM clients WHERE created_by = $1";
    const countParams = [req.user.id];
    if (status) countQuery += ` AND status = $2`;
    if (status) countParams.push(status);

    const countResult = await pool.query(countQuery, countParams);
    const total = parseInt(countResult.rows[0].count);

    res.json({
      clients: result.rows,
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
      "SELECT * FROM clients WHERE id = $1 AND created_by = $2",
      [req.params.id, req.user.id]
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

    const result = await pool.query(
      `UPDATE clients 
       SET name = $1, email = $2, phone = $3, address = $4, latitude = $5, longitude = $6, status = $7, notes = $8
       WHERE id = $9 AND created_by = $10
       RETURNING *`,
      [name, email, phone, address, latitude, longitude, status, notes, req.params.id, req.user.id]
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
      "DELETE FROM clients WHERE id = $1 AND created_by = $2 RETURNING id",
      [req.params.id, req.user.id]
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

// CREATE LOCATION LOG
// GET LOCATION LOGS (with date filtering)
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

    // 🔧 Map snake_case columns to camelCase for app
    const mappedLogs = result.rows.map(log => ({
      id: log.id,
      userId: log.user_id,           // ← Fix here
      latitude: log.latitude,
      longitude: log.longitude,
      accuracy: log.accuracy,
      activity: log.activity,
      notes: log.notes,
      timestamp: log.timestamp
    }));

    res.json({
      logs: mappedLogs,                // ← Use mapped data
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


//============================================
// LOCATION POST
//===========================================

// CREATE LOCATION LOG
app.post("/location-logs", authenticateToken, async (req, res) => {
  try {
    const { latitude, longitude, accuracy, activity, notes } = req.body;

    if (!latitude || !longitude) {
      return res.status(400).json({ error: "LocationRequired" });
    }

    const result = await pool.query(
      `INSERT INTO location_logs (user_id, latitude, longitude, accuracy, activity, notes)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [req.user.id, latitude, longitude, accuracy || null, activity || null, notes || null]
    );

    // 🔧 Map response to camelCase
    const log = result.rows[0];
    const mappedLog = {
      id: log.id,
      userId: log.user_id,           // ← Fix here
      latitude: log.latitude,
      longitude: log.longitude,
      accuracy: log.accuracy,
      activity: log.activity,
      notes: log.notes,
      timestamp: log.timestamp
    };

    res.status(201).json({
      message: "LocationLogged",
      log: mappedLog                  // ← Use mapped data
    });
  } catch (err) {
    console.error("CREATE LOCATION LOG ERROR:", err);
    res.status(500).json({ error: "CreateLocationLogFailed" });
  }
});



// ============================================
// TALLY SYNC ROUTES (Add to your server.js)
// ============================================

// Middleware token for service-to-service auth
const MIDDLEWARE_TOKEN = process.env.MIDDLEWARE_TOKEN || "tally-middleware-secret-key-12345";

// Verify Middleware Token
const authenticateMiddleware = (req, res, next) => {
  const token = req.headers["x-middleware-token"];

  if (!token) {
    return res.status(401).json({ error: "MiddlewareTokenRequired" });
  }

  if (token !== MIDDLEWARE_TOKEN) {
    return res.status(403).json({ error: "InvalidMiddlewareToken" });
  }

  next();
};



// ============================================
// SYNC CLIENTS FROM TALLY
// ============================================
app.post("/api/sync/tally-clients", authenticateMiddleware, async (req, res) => {
  const client = await pool.connect();
  
  try {
    const { clients: tallyClients } = req.body;

    if (!tallyClients || !Array.isArray(tallyClients)) {
      return res.status(400).json({ error: "InvalidPayload", message: "Expected array of clients" });
    }

    console.log(`📥 Tally sync started: ${tallyClients.length} clients received`);

    // Start transaction
    await client.query("BEGIN");

    let newCount = 0;
    let updatedCount = 0;
    let failedCount = 0;
    const errors = [];

    // Process each client
    for (const tallyClient of tallyClients) {
      try {
        const {
          tally_guid,
          name,
          email,
          phone,
          address,
          latitude,
          longitude,
          status = "active",
          notes
        } = tallyClient;

        // Validate required fields
        if (!name) {
          failedCount++;
          errors.push({ tally_guid, error: "Missing name" });
          continue;
        }

        // Check if client exists (by tally_guid or email)
        let existingClient = null;
        
        if (tally_guid) {
          // Check in mapping table first
          const mappingResult = await client.query(
            "SELECT client_id FROM tally_client_mapping WHERE tally_ledger_id = $1",
            [tally_guid]
          );
          
          if (mappingResult.rows.length > 0) {
            const clientId = mappingResult.rows[0].client_id;
            const clientResult = await client.query(
              "SELECT * FROM clients WHERE id = $1",
              [clientId]
            );
            existingClient = clientResult.rows[0];
          }
        }
        
        // Fallback: Check by email if no mapping found
        if (!existingClient && email) {
          const emailResult = await client.query(
            "SELECT * FROM clients WHERE email = $1 AND created_by = 'b04316f8-3bfb-492d-99e3-9e703f791fc8'",
            [email]
          );
          if (emailResult.rows.length > 0) {
            existingClient = emailResult.rows[0];
          }
        }

        let clientId;

        if (existingClient) {
          // UPDATE existing client
          const updateResult = await client.query(
            `UPDATE clients 
             SET name = $1, email = $2, phone = $3, address = $4, 
                 latitude = $5, longitude = $6, status = $7, notes = $8, 
                 updated_at = NOW()
             WHERE id = $9
             RETURNING id`,
            [name, email, phone, address, latitude, longitude, status, notes, existingClient.id]
          );
          
          clientId = updateResult.rows[0].id;
          updatedCount++;
          console.log(`✏️  Updated: ${name} (${clientId})`);
        } else {
          // INSERT new client
          const insertResult = await client.query(
  `INSERT INTO clients 
   (name, email, phone, address, latitude, longitude, status, notes, created_by)
   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, '8eaf9602-c9f1-4e13-8aa5-988e93896d6a')
   RETURNING id`,
  [name, email, phone, address, latitude, longitude, status, notes]
);

          
          clientId = insertResult.rows[0].id;
          newCount++;
          console.log(`✨ Created: ${name} (${clientId})`);
        }

        // Update or create mapping
        if (tally_guid) {
          await client.query(
            `INSERT INTO tally_client_mapping (tally_ledger_id, client_id, last_synced_at, sync_status)
             VALUES ($1, $2, NOW(), 'synced')
             ON CONFLICT (tally_ledger_id) 
             DO UPDATE SET client_id = $2, last_synced_at = NOW(), sync_status = 'synced'`,
            [tally_guid, clientId]
          );
        }

      } catch (error) {
        failedCount++;
        errors.push({ 
          tally_guid: tallyClient.tally_guid, 
          name: tallyClient.name,
          error: error.message 
        });
        console.error(`❌ Failed to sync client: ${tallyClient.name}`, error.message);
      }
    }

    // Log sync results
    await client.query(
      `INSERT INTO tally_sync_log 
       (sync_started_at, sync_completed_at, total_records, new_records, updated_records, failed_records, errors, status, triggered_by)
       VALUES (NOW(), NOW(), $1, $2, $3, $4, $5, 'completed', 'middleware')`,
      [
        tallyClients.length,
        newCount,
        updatedCount,
        failedCount,
        JSON.stringify(errors)
      ]
    );

    // Commit transaction
    await client.query("COMMIT");

    console.log(`✅ Tally sync completed: ${newCount} new, ${updatedCount} updated, ${failedCount} failed`);

    res.status(200).json({
      message: "SyncCompleted",
      summary: {
        total: tallyClients.length,
        new: newCount,
        updated: updatedCount,
        failed: failedCount
      },
      errors: errors.length > 0 ? errors : undefined
    });

  } catch (err) {
    await client.query("ROLLBACK");
    console.error("TALLY SYNC ERROR:", err);
    
    // Log failed sync
    try {
      await client.query(
        `INSERT INTO tally_sync_log 
         (sync_started_at, sync_completed_at, total_records, failed_records, errors, status, triggered_by)
         VALUES (NOW(), NOW(), 0, 0, $1, 'failed', 'middleware')`,
        [JSON.stringify([{ error: err.message }])]
      );
    } catch (logError) {
      console.error("Failed to log sync error:", logError);
    }
    
    res.status(500).json({ error: "SyncFailed", message: err.message });
  } finally {
    client.release();
  }
});

// ============================================
// GET SYNC STATUS
// ============================================
app.get("/api/sync/status", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM tally_sync_log 
       ORDER BY sync_started_at DESC 
       LIMIT 10`
    );

    res.json({
      syncs: result.rows.map(row => ({
        id: row.id,
        startedAt: row.sync_started_at,
        completedAt: row.sync_completed_at,
        total: row.total_records,
        new: row.new_records,
        updated: row.updated_records,
        failed: row.failed_records,
        status: row.status,
        triggeredBy: row.triggered_by,
        errors: row.errors ? JSON.parse(row.errors) : []
      }))
    });
  } catch (err) {
    console.error("GET SYNC STATUS ERROR:", err);
    res.status(500).json({ error: "GetSyncStatusFailed" });
  }
});

// ============================================
// GET LATEST SYNC INFO
// ============================================
app.get("/api/sync/latest", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM tally_sync_log 
       WHERE status = 'completed'
       ORDER BY sync_started_at DESC 
       LIMIT 1`
    );

    if (result.rows.length === 0) {
      return res.json({ 
        message: "NoSyncsYet",
        lastSync: null 
      });
    }

    const sync = result.rows[0];
    res.json({
      lastSync: {
        completedAt: sync.sync_completed_at,
        total: sync.total_records,
        new: sync.new_records,
        updated: sync.updated_records,
        failed: sync.failed_records,
        status: sync.status
      }
    });
  } catch (err) {
    console.error("GET LATEST SYNC ERROR:", err);
    res.status(500).json({ error: "GetLatestSyncFailed" });
  }
});

// ============================================
// MANUAL TRIGGER SYNC (Optional - calls middleware)
// ============================================
app.post("/api/sync/trigger", authenticateToken, async (req, res) => {
  try {
    // This endpoint would call your middleware to start a sync
    // For now, just log the request
    
    await pool.query(
      `INSERT INTO tally_sync_log 
       (sync_started_at, total_records, status, triggered_by)
       VALUES (NOW(), 0, 'running', 'manual')
       RETURNING id`
    );

    res.json({ 
      message: "SyncTriggered",
      note: "Middleware should start syncing now"
    });
  } catch (err) {
    console.error("TRIGGER SYNC ERROR:", err);
    res.status(500).json({ error: "TriggerSyncFailed" });
  }
});








// ============================================
// UTILITY ROUTES
// ============================================

app.get("/", (req, res) => {
  res.json({ message: "Client Tracking API Running" });
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
  console.log(`📚 API Endpoints:`);
  console.log(`   Auth:`);
  console.log(`     POST   /auth/signup`);
  console.log(`     POST   /auth/login`);
  console.log(`     POST   /auth/forgot-password`);
  console.log(`     POST   /auth/reset-password`);
  console.log(`     GET    /auth/profile`);
  console.log(`     PUT    /auth/profile`);
  console.log(`   Clients:`);
  console.log(`     POST   /clients`);
  console.log(`     GET    /clients`);
  console.log(`     GET    /clients/:id`);
  console.log(`     PUT    /clients/:id`);
  console.log(`     DELETE /clients/:id`);
  console.log(`   Location:`);
  console.log(`     POST   /location-logs`);
  console.log(`     GET    /location-logs`);
});