import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import xlsx from "xlsx";
import multer from "multer";
import { pool } from "./db.js";
import { startBackgroundGeocode } from "./utils/geocodeBatch.js";

const app = express();
app.use(cors({
  origin: [
    "http://localhost:3000", 
    "https://geo-track-em3s.onrender.com"
  ],
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.options("*", cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "your-super-secret-jwt-key-change-in-production";
const PORT = process.env.PORT || 5000;
const GOOGLE_MAPS_API_KEY = process.env.GOOGLE_MAPS_API_KEY;
const MIDDLEWARE_TOKEN = process.env.MIDDLEWARE_TOKEN || "tally-middleware-secret-key-12345";

// Test DB connection
pool.query("SELECT NOW()", (err, res) => {
  if (err) {
    console.error("❌ Database connection failed:", err);
  } else {
    console.log("✅ Database connected successfully");
  }
});

const upload = multer({ storage: multer.memoryStorage() });

// ============================================
// HELPER FUNCTIONS
// ============================================

const getPincodeFromCoordinates = async (latitude, longitude) => {
  try {
    const response = await fetch(
      `https://maps.googleapis.com/maps/api/geocode/json?latlng=${latitude},${longitude}&region=in&key=${GOOGLE_MAPS_API_KEY}`
    );
    
    const data = await response.json();
    
    if (data.status === 'OK' && data.results.length > 0) {
      const addressComponents = data.results[0].address_components;
      const pincodeComponent = addressComponents.find(
        component => component.types.includes('postal_code')
      );
      
      const pincode = pincodeComponent?.long_name || null;
      console.log(`📍 Google: (${latitude}, ${longitude}) → Pincode: ${pincode}`);
      return pincode;
    }
    
    console.log(`⚠️ Google API returned: ${data.status}`);
    return null;
  } catch (error) {
    console.error("❌ Google Geocoding error:", error);
    return null;
  }
};

async function getCoordinatesFromPincode(pincode) {
  try {
    const url = `https://maps.googleapis.com/maps/api/geocode/json?address=${pincode}&region=in&key=${GOOGLE_MAPS_API_KEY}`;
    const res = await fetch(url);
    const data = await res.json();
    if (data.status !== "OK") return null;

    const loc = data.results[0].geometry.location;
    return { latitude: loc.lat, longitude: loc.lng };
  } catch {
    return null;
  }
}

async function getCoordinatesFromAddress(address) {
  try {
    const url = `https://maps.googleapis.com/maps/api/geocode/json?address=${encodeURIComponent(address)}&key=${GOOGLE_MAPS_API_KEY}`;
    const res = await fetch(url);
    const data = await res.json();
    if (data.status !== "OK") return null;

    const loc = data.results[0].geometry.location;
    const components = data.results[0].address_components;
    const pincode = components.find((c) =>
      c.types.includes("postal_code")
    )?.long_name;

    return { latitude: loc.lat, longitude: loc.lng, pincode };
  } catch {
    return null;
  }
}

// ============================================
// MIDDLEWARE
// ============================================

app.use((req, res, next) => {
  console.log(`📥 ${req.method} ${req.path}`);
  next();
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "AccessTokenRequired" });
  }

  jwt.verify(token, JWT_SECRET, async (err, decoded) => {
    if (err) return res.status(403).json({ error: "InvalidToken" });

    const result = await pool.query(
      `SELECT * FROM user_sessions WHERE token = $1 AND expires_at > NOW()`,
      [token]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "SessionExpired" });
    }

    req.user = decoded;
    next();
  });
};

const requireAdmin = (req, res, next) => {
  if (!req.user || !req.user.isAdmin) {
    return res.status(403).json({ error: "AdminOnly" });
  }
  next();
};

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
// AUTH ROUTES
// ============================================

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

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        isAdmin: user.is_admin
      },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    await pool.query(
      `INSERT INTO user_sessions (user_id, token, expires_at)
       VALUES ($1, $2, NOW() + INTERVAL '7 days')`,
      [user.id, token]
    );

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

app.post("/auth/logout", authenticateToken, async (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  await pool.query(`DELETE FROM user_sessions WHERE token = $1`, [token]);
  res.json({ message: "LogoutSuccess" });
});

app.post("/auth/signup", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "MissingFields" });
    }

    const existing = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({ error: "EmailAlreadyExists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const userResult = await pool.query(
      `INSERT INTO users (email, password, is_admin)
       VALUES ($1, $2, false)
       RETURNING id, email`,
      [email, hashedPassword]
    );

    const user = userResult.rows[0];

    await pool.query(
      `INSERT INTO profiles (user_id) VALUES ($1)`,
      [user.id]
    );

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        isAdmin: false
      },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    await pool.query(
      `INSERT INTO user_sessions (user_id, token, expires_at)
       VALUES ($1, $2, NOW() + INTERVAL '7 days')`,
      [user.id, token]
    );

    res.status(201).json({
      message: "SignupSuccess",
      token,
      user,
    });
  } catch (err) {
    console.error("SIGNUP ERROR:", err);
    res.status(500).json({ error: "SignupFailed" });
  }
});

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
    const resetTokenExpiry = new Date(Date.now() + 3600000);

    await pool.query(
      "UPDATE users SET reset_token = $1, reset_token_expiry = $2 WHERE email = $3",
      [resetToken, resetTokenExpiry, email]
    );

    console.log("🔑 Password Reset Token:", resetToken);
    console.log("📧 For Email:", email);

    res.json({
      message: "PasswordResetEmailSent",
      resetToken: resetToken,
    });
  } catch (err) {
    console.error("FORGOT PASSWORD ERROR:", err);
    res.status(500).json({ error: "ForgotPasswordFailed" });
  }
});

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

app.post("/auth/clear-pincode", authenticateToken, async (req, res) => {
  try {
    await pool.query(
      `UPDATE users SET pincode = NULL WHERE id = $1`,
      [req.user.id]
    );
    console.log(`🛑 Tracking stopped → cleared pincode for ${req.user.id}`);
    res.json({ message: "PincodeCleared" });
  } catch (err) {
    res.status(500).json({ error: "ClearPincodeFailed" });
  }
});

// ============================================
// CLIENTS ROUTES
// ============================================

// Replace the entire Excel upload route in your server.js
// Starting from app.post("/clients/upload-excel", ...)
// Replace the entire duplicate checking section in your Excel upload route

app.post(
  "/clients/upload-excel",
  authenticateToken,
  upload.single("file"),
  async (req, res) => {
    const client = await pool.connect();
    
    try {
      if (!req.file) {
        return res.status(400).json({ error: "NoFileUploaded" });
      }

      console.log("📥 Upload started:", req.file.originalname, req.file.size, "bytes");

      if (req.file.mimetype !== "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet") {
        return res.status(400).json({ error: "OnlyXLSXAllowed" });
      }

      const workbook = xlsx.read(req.file.buffer, { type: "buffer" });
      const sheet = workbook.Sheets[workbook.SheetNames[0]];
      const rows = xlsx.utils.sheet_to_json(sheet);

      if (rows.length === 0) {
        return res.status(400).json({ error: "EmptyExcelFile" });
      }

      console.log(`📊 Processing ${rows.length} rows...`);

      await client.query("BEGIN");

      let imported = 0;
      let updated = 0;
      let skipped = 0;

      for (const row of rows) {
        const name = row.name || row.Name || null;
        const email = row.email || row.Email || null;
        
        let phone = row.phone || row.Phone || null;
        if (phone !== null && phone !== undefined && phone !== '') {
          phone = String(phone).trim().replace(/\s+/g, '');
        } else {
          phone = null;
        }
        
        const address = row.address || row.Address || null;
        const note = row.note || row.Note || row.notes || row.Notes || null;
        const status = row.status || row.Status || 'active';
        const source = row.source || row.Source || 'excel';

        let latitude = null;
        let longitude = null;
        let pincode = null;

        if (row.latitude || row.Latitude) {
          latitude = parseFloat(row.latitude || row.Latitude);
          if (isNaN(latitude)) latitude = null;
        }

        if (row.longitude || row.Longitude) {
          longitude = parseFloat(row.longitude || row.Longitude);
          if (isNaN(longitude)) longitude = null;
        }

        if (row.pincode || row.Pincode) {
          pincode = String(row.pincode || row.Pincode).trim();
          if (pincode.includes('.')) {
            pincode = pincode.split('.')[0];
          }
        }

        if (!name || !address) {
          console.log(`⚠️ Skipping row: missing name or address`);
          skipped++;
          continue;
        }

        // Geocode if needed
        if (pincode && (!latitude || !longitude)) {
          try {
            const geo = await getCoordinatesFromPincode(pincode);
            if (geo) {
              latitude = geo.latitude;
              longitude = geo.longitude;
              console.log(`🔍 Geocoded ${name} from pincode ${pincode}`);
            }
          } catch (err) {
            console.log(`⚠️ Geocoding failed for pincode ${pincode}`);
          }
        }

        if (!pincode && address && (!latitude || !longitude)) {
          try {
            const geo = await getCoordinatesFromAddress(address);
            if (geo) {
              latitude = latitude ?? geo.latitude;
              longitude = longitude ?? geo.longitude;
              pincode = pincode ?? geo.pincode;
              console.log(`🔍 Geocoded ${name} from address`);
            }
          } catch (err) {
            console.log(`⚠️ Geocoding failed for address: ${address}`);
          }
        }

        // ========== ✅ FIXED DUPLICATE CHECKING (USER-SPECIFIC) ==========
        let duplicateCheck = { rows: [] };
        
        // Check 1: By email (for THIS USER only)
        if (email) {
          duplicateCheck = await client.query(
            `SELECT id FROM clients 
             WHERE LOWER(TRIM(email)) = LOWER(TRIM($1)) 
             AND created_by = $2 
             LIMIT 1`,
            [email, req.user.id]
          );
        }
        
        // Check 2: By phone (for THIS USER only)
        if (duplicateCheck.rows.length === 0 && phone) {
          const cleanPhone = phone.replace(/\D/g, '');
          
          if (cleanPhone.length >= 10) {
            duplicateCheck = await client.query(
              `SELECT id FROM clients 
               WHERE REGEXP_REPLACE(phone, '\\D', '', 'g') = $1 
               AND created_by = $2
               LIMIT 1`,
              [cleanPhone, req.user.id]
            );
          }
        }
        
        // Check 3: By name + pincode (for THIS USER only)
        if (duplicateCheck.rows.length === 0) {
          const cleanName = name.toLowerCase().trim().replace(/[^a-z0-9\s]/g, '');
          
          if (pincode) {
            duplicateCheck = await client.query(
              `SELECT id FROM clients 
               WHERE LOWER(TRIM(REGEXP_REPLACE(name, '[^a-zA-Z0-9\\s]', '', 'g'))) = $1 
               AND pincode = $2
               AND created_by = $3
               LIMIT 1`,
              [cleanName, pincode, req.user.id]
            );
          } else {
            duplicateCheck = await client.query(
              `SELECT id FROM clients 
               WHERE LOWER(TRIM(REGEXP_REPLACE(name, '[^a-zA-Z0-9\\s]', '', 'g'))) = $1
               AND created_by = $2
               LIMIT 1`,
              [cleanName, req.user.id]
            );
          }
        }

        // ========== UPDATE OR INSERT (Only user's own records) ==========
        if (duplicateCheck.rows.length > 0) {
          // Update THIS USER's existing client
          const existingId = duplicateCheck.rows[0].id;
          
          await client.query(
            `UPDATE clients 
             SET 
               email = COALESCE($1, email),
               phone = COALESCE($2, phone),
               address = COALESCE($3, address),
               latitude = COALESCE($4, latitude),
               longitude = COALESCE($5, longitude),
               pincode = COALESCE($6, pincode),
               notes = COALESCE($7, notes),
               status = $8,
               updated_at = NOW()
             WHERE id = $9 AND created_by = $10`,
            [email, phone, address, latitude, longitude, pincode, note, status, existingId, req.user.id]
          );

          updated++;
          console.log(`🔄 Updated: ${name} (ID: ${existingId}) for user ${req.user.id}`);
          
        } else {
          // Insert new client for THIS USER
          await client.query(
            `INSERT INTO clients
             (name, email, phone, address, latitude, longitude, status, notes, created_by, source, pincode)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
            [name, email, phone, address, latitude, longitude, status, note, req.user.id, source, pincode]
          );

          imported++;
          console.log(`✅ Imported: ${name} for user ${req.user.id}`);
        }
      }

      await client.query("COMMIT");

      const summary = {
        total: rows.length,
        imported,
        updated,
        skipped
      };

      console.log("✅ Upload completed:", summary);

      res.json({
        status: "OK",
        summary
      });

    } catch (error) {
      await client.query("ROLLBACK");
      console.error("❌ Upload error:", error);
      console.error("Stack trace:", error.stack);
      
      res.status(500).json({ 
        error: "UploadFailed", 
        message: error.message 
      });
    } finally {
      client.release();
    }
  }
);

app.post("/clients", authenticateToken, async (req, res) => {
  try {
    const { name, email, phone, address, latitude, longitude, status, notes } = req.body;

    if (!name) {
      return res.status(400).json({ error: "ClientNameRequired" });
    }

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

app.get("/clients", authenticateToken, async (req, res) => {
  try {
    const { status, search, page = 1, limit = 100 } = req.query;
    const offset = (page - 1) * limit;

    console.log(`👤 Fetching clients for user: ${req.user.id}`);

    const userPincode = (await pool.query("SELECT pincode FROM users WHERE id = $1", [req.user.id])).rows[0]?.pincode;
    if (!userPincode) {
      return res.status(400).json({ 
        error: "NoPincodeFound",
        message: "Please enable location tracking first. No location data available."
      });
    }

    console.log(`📍 Filtering clients by pincode: ${userPincode}`);

    let query = `
      SELECT *
      FROM clients
      WHERE pincode = $1
      AND (created_by IS NULL OR created_by = $2)
    `;
    const params = [userPincode, req.user.id];
    let paramCount = 2;

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

app.put("/clients/:id", authenticateToken, async (req, res) => {
  try {
    const { name, email, phone, address, latitude, longitude, status, notes } = req.body;

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

app.post("/location-logs", authenticateToken, async (req, res) => {
  try {
    const { latitude, longitude, accuracy, activity, notes, battery } = req.body;

    if (!latitude || !longitude) {
      return res.status(400).json({ error: "LocationRequired" });
    }

    console.log(`📍 Logging location for user ${req.user.id}: ${latitude}, ${longitude}`);

    const pincode = await getPincodeFromCoordinates(latitude, longitude);

    const result = await pool.query(
      `INSERT INTO location_logs (user_id, latitude, longitude, accuracy, activity, notes, pincode, battery)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING *`,
      [req.user.id, latitude, longitude, accuracy || null, activity || null, notes || null, pincode, battery || null]
    );

    if (pincode) {
      await pool.query(
        `UPDATE users SET pincode = $1 WHERE id = $2 AND pincode IS DISTINCT FROM $1`,
        [pincode, req.user.id]
      );
      console.log(`📌 Updated user pincode to ${pincode} for user ${req.user.id}`);
    }

    const log = result.rows[0];
    const mappedLog = {
      id: log.id,
      userId: log.user_id,
      latitude: log.latitude,
      longitude: log.longitude,
      accuracy: log.accuracy,
      battery: log.battery,
      activity: log.activity,
      notes: log.notes,
      pincode: log.pincode,
      timestamp: log.timestamp
    };

    console.log(`🔋 Battery logged for user ${req.user.id}: ${battery}% @ ${latitude}, ${longitude}`);
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

app.get("/location-logs/clock-in", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT latitude, longitude, timestamp
       FROM location_logs
       WHERE user_id = $1
         AND DATE(timestamp) = CURRENT_DATE
       ORDER BY timestamp ASC
       LIMIT 1`,
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.json({ clockIn: null });
    }

    res.json({ clockIn: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: "ClockInFetchFailed" });
  }
});

// ============================================
// TALLY SYNC ROUTES (NEW IMPLEMENTATION)
// ============================================

app.post("/api/sync/tally-clients", authenticateMiddleware, async (req, res) => {
  const client = await pool.connect();
  
  try {
    const { clients: tallyClients } = req.body;

    if (!tallyClients || !Array.isArray(tallyClients)) {
      return res.status(400).json({ 
        error: "InvalidPayload", 
        message: "Expected array of clients" 
      });
    }

    console.log(`🔥 Tally sync started: ${tallyClients.length} clients received`);

    await client.query("BEGIN");

    let newCount = 0;
    let updatedCount = 0;
    let failedCount = 0;
    const errors = [];

    for (const tallyClient of tallyClients) {
      try {
        const {
          tally_guid,
          name,
          email,
          phone,
          address,
          pincode,
          latitude,
          longitude,
          status = "active",
          notes,
          source = "tally"
        } = tallyClient;

        if (!name) {
          failedCount++;
          errors.push({ tally_guid, error: "Missing name" });
          continue;
        }

        let existingClient = null;
        
        if (tally_guid) {
          const guidResult = await client.query(
            "SELECT * FROM clients WHERE tally_guid = $1 LIMIT 1",
            [tally_guid]
          );
          if (guidResult.rows.length > 0) {
            existingClient = guidResult.rows[0];
          }
        }
        
        if (!existingClient && email) {
          const emailResult = await client.query(
            "SELECT * FROM clients WHERE LOWER(TRIM(email)) = LOWER(TRIM($1)) LIMIT 1",
            [email]
          );
          if (emailResult.rows.length > 0) {
            existingClient = emailResult.rows[0];
          }
        }

        if (!existingClient && phone) {
          const cleanPhone = phone.replace(/\D/g, '');
          if (cleanPhone.length >= 10) {
            const phoneResult = await client.query(
              "SELECT * FROM clients WHERE REGEXP_REPLACE(phone, '\\D', '', 'g') = $1 LIMIT 1",
              [cleanPhone]
            );
            if (phoneResult.rows.length > 0) {
              existingClient = phoneResult.rows[0];
            }
          }
        }

        let clientId;

        if (existingClient) {
          const updateResult = await client.query(
            `UPDATE clients 
             SET name = $1, 
                 email = COALESCE($2, email), 
                 phone = COALESCE($3, phone), 
                 address = COALESCE($4, address), 
                 latitude = COALESCE($5, latitude), 
                 longitude = COALESCE($6, longitude), 
                 status = $7, 
                 notes = COALESCE($8, notes), 
                 pincode = COALESCE($9, pincode),
                 tally_guid = COALESCE($10, tally_guid),
                 source = $11,
                 updated_at = NOW()
             WHERE id = $12
             RETURNING id`,
            [
              name, email, phone, address, latitude, longitude, 
              status, notes, pincode, tally_guid, source, existingClient.id
            ]
          );
          
          clientId = updateResult.rows[0].id;
          updatedCount++;
          console.log(`✏️ Updated: ${name} (${clientId})`);

        } else {
          const insertResult = await client.query(
            `INSERT INTO clients 
             (name, email, phone, address, latitude, longitude, status, notes, 
              pincode, tally_guid, source, created_by)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NULL)
             RETURNING id`,
            [name, email, phone, address, latitude, longitude, status, notes, 
             pincode, tally_guid, source]
          );
          
          clientId = insertResult.rows[0].id;
          newCount++;
          console.log(`✨ Created: ${name} (${clientId})`);
        }

        if (tally_guid && clientId) {
          await client.query(
            `INSERT INTO tally_client_mapping (tally_ledger_id, client_id, last_synced_at, sync_status)
             VALUES ($1, $2, NOW(), 'synced')
             ON CONFLICT (tally_ledger_id) 
             DO UPDATE SET client_id = $2, last_synced_at = NOW(), sync_status = 'synced'`,
            [tally_guid, clientId]
          );
        }

      } catch (error) {
        console.error(`❌ Failed to sync ${tallyClient.name}:`, error.message);
        failedCount++;
        errors.push({ 
          tally_guid: tallyClient.tally_guid, 
          name: tallyClient.name,
          error: error.message 
        });
        
        if (error.message.includes('duplicate key') || 
            error.message.includes('violates') ||
            error.message.includes('constraint')) {
          console.log(`⚠️ Continuing despite error for ${tallyClient.name}`);
        }
      }
    }

    await client.query(
      `INSERT INTO tally_sync_log 
       (sync_started_at, sync_completed_at, total_records, new_records, 
        updated_records, failed_records, errors, status, triggered_by)
       VALUES (NOW(), NOW(), $1, $2, $3, $4, $5, 'completed', 'middleware')`,
      [tallyClients.length, newCount, updatedCount, failedCount, JSON.stringify(errors)]
    );

    await client.query("COMMIT");

    // ✅ Trigger background geocoding for clients missing location data
    startBackgroundGeocode();

    console.log(`✅ Tally sync completed:`);
    console.log(`   📊 Total: ${tallyClients.length}`);

    console.log(`✅ Tally sync completed:`);
    console.log(`   📊 Total: ${tallyClients.length}`);
    console.log(`   ✨ New: ${newCount}`);
    console.log(`   ✏️ Updated: ${updatedCount}`);
    console.log(`   ❌ Failed: ${failedCount}`);

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
    console.error("❌ TALLY SYNC ERROR:", err);
    console.error("Stack:", err.stack);
    
    try {
      await pool.query(
        `INSERT INTO tally_sync_log 
         (sync_started_at, sync_completed_at, total_records, failed_records, 
          errors, status, triggered_by)
         VALUES (NOW(), NOW(), 0, 0, $1, 'failed', 'middleware')`,
        [JSON.stringify([{ error: err.message, stack: err.stack }])]
      );
    } catch (logError) {
      console.error("Failed to log sync error:", logError);
    }
    
    res.status(500).json({ 
      error: "SyncFailed", 
      message: err.message,
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });

  } finally {
    client.release();
  }
});

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

app.post("/api/sync/trigger", authenticateToken, async (req, res) => {
  try {
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
// ADMIN ROUTES (FIXED VERSION)
// ============================================

app.get("/admin/clients", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { status, search, page = 1, limit = 1000 } = req.query;
    const offset = (page - 1) * limit;

    let query = "SELECT * FROM clients WHERE 1=1";
    const params = [];
    let paramCount = 0;

    if (status) {
      paramCount++;
      query += ` AND status = $${paramCount}`;
      params.push(status);
    }

    if (search) {
      paramCount++;
      query += ` AND (name ILIKE $${paramCount} OR email ILIKE $${paramCount})`;
      params.push(`%${search}%`);
    }

    query += ` ORDER BY created_at DESC LIMIT $${paramCount + 1} OFFSET $${paramCount + 2}`;
    params.push(limit, offset);

    const result = await pool.query(query, params);
    const countResult = await pool.query("SELECT COUNT(*) FROM clients");
    const total = parseInt(countResult.rows[0].count);

    console.log(`✅ Admin fetched ${result.rows.length} clients`);

    res.json({
      clients: result.rows,
      pagination: { 
        page: parseInt(page), 
        limit: parseInt(limit), 
        total, 
        totalPages: Math.ceil(total / limit) 
      }
    });
  } catch (err) {
    console.error("ADMIN CLIENTS ERROR:", err);
    res.status(500).json({ error: "GetAdminClientsFailed", message: err.message });
  }
});

app.get("/admin/users", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { limit = 1000 } = req.query;
    
    const result = await pool.query(
      `SELECT u.id, u.email, u.created_at, u.pincode,
              p.full_name, p.department, p.work_hours_start, p.work_hours_end
       FROM users u
       LEFT JOIN profiles p ON u.id = p.user_id
       ORDER BY u.created_at DESC
       LIMIT $1`,
      [limit]
    );

    console.log(`✅ Admin fetched ${result.rows.length} users`);

    res.json({ users: result.rows });
  } catch (err) {
    console.error("ADMIN USERS ERROR:", err);
    res.status(500).json({ error: "GetAdminUsersFailed", message: err.message });
  }
});

app.get("/admin/analytics", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const clientStats = await pool.query(`
      SELECT 
        COUNT(*) as total_clients,
        COUNT(CASE WHEN status = 'active' THEN 1 END) as active_clients,
        COUNT(CASE WHEN latitude IS NOT NULL AND longitude IS NOT NULL THEN 1 END) as clients_with_location,
        COUNT(DISTINCT pincode) FILTER (WHERE pincode IS NOT NULL) as unique_pincodes
      FROM clients
    `);

    const userStats = await pool.query(`SELECT COUNT(*) as total_users FROM users`);
    const locationStats = await pool.query(`SELECT COUNT(*) as total_logs FROM location_logs`);

    console.log("✅ Admin analytics fetched successfully");

    res.json({
      clients: clientStats.rows[0],
      users: userStats.rows[0],
      locations: locationStats.rows[0]
    });
  } catch (err) {
    console.error("ADMIN ANALYTICS ERROR:", err);
    res.status(500).json({ error: "GetAdminAnalyticsFailed", message: err.message });
  }
});

app.get("/admin/location-logs/:userId", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 200 } = req.query;
    const offset = (page - 1) * limit;
    const userId = req.params.userId;

    const result = await pool.query(
      `SELECT id, latitude, longitude, accuracy, activity, battery, notes, pincode, timestamp
       FROM location_logs
       WHERE user_id = $1
       ORDER BY timestamp DESC
       LIMIT $2 OFFSET $3`,
      [userId, limit, offset]
    );

    const countResult = await pool.query(
      "SELECT COUNT(*) FROM location_logs WHERE user_id = $1",
      [userId]
    );

    console.log(`✅ Fetched ${result.rows.length} logs for user ${userId}`);

    res.json({
      logs: result.rows,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: parseInt(countResult.rows[0].count),
        totalPages: Math.ceil(countResult.rows[0].count / limit),
      }
    });

  } catch (err) {
    console.error("GET ADMIN LOCATION LOGS ERROR:", err);
    res.status(500).json({ error: "GetAdminLocationLogsFailed", message: err.message });
  }
});

app.get("/admin/clock-status/:userId", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;

    const result = await pool.query(`
      SELECT timestamp
      FROM location_logs
      WHERE user_id = $1
      ORDER BY timestamp DESC
      LIMIT 1
    `, [userId]);

    if (result.rows.length === 0) {
      return res.json({ clocked_in: false, last_seen: null });
    }

    const lastSeen = new Date(result.rows[0].timestamp);
    const now = new Date();
    const diffMinutes = (now - lastSeen) / (1000 * 60);
    
    // Consider active if logged location within last 5 minutes
    const isActive = diffMinutes <= 5;

    res.json({
      clocked_in: isActive,
      last_seen: lastSeen.toISOString()
    });
  } catch (err) {
    console.error("GET CLOCK STATUS ERROR:", err);
    res.status(500).json({ error: "GetClockStatusFailed", message: err.message });
  }
});

app.get("/admin/expenses/summary", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id,
        COALESCE(SUM(e.amount_spent), 0) AS total_expense
      FROM users u
      LEFT JOIN trip_expenses e ON e.user_id = u.id
      GROUP BY u.id
      ORDER BY u.id
    `);

    console.log(`✅ Fetched expense summary for ${result.rows.length} users`);

    res.json({ summary: result.rows });
  } catch (err) {
    console.error("GET EXPENSES SUMMARY ERROR:", err);
    res.status(500).json({ error: "GetExpensesSummaryFailed", message: err.message });
  }
});

// ----------------------------------------------
// ADMIN: GET PAGINATED USER MEETINGS
// ----------------------------------------------
app.get("/admin/user-meetings/:userId", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const userId = req.params.userId;

    // Pagination parameters
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;

    // Count total meetings (for pagination UI)
    const totalCountResult = await pool.query(
      `SELECT COUNT(*) FROM meetings WHERE user_id = $1`,
      [userId]
    );
    const totalCount = parseInt(totalCountResult.rows[0].count);

    // Fetch paginated meetings + joined client data
    const result = await pool.query(
      `SELECT 
         m.id,
         m.user_id AS "userId",
         m.client_id AS "clientId",
         m.start_time AS "startTime",
         m.end_time AS "endTime",
         m.start_latitude AS "startLatitude",
         m.start_longitude AS "startLongitude",
         m.start_accuracy AS "startAccuracy",
         m.end_latitude AS "endLatitude",
         m.end_longitude AS "endLongitude",
         m.end_accuracy AS "endAccuracy",
         m.status,
         m.comments,
         m.attachments,
         m.created_at AS "createdAt",
         m.updated_at AS "updatedAt",
         c.name AS "clientName",
         c.address AS "clientAddress"
       FROM meetings m
       LEFT JOIN clients c ON m.client_id = c.id
       WHERE m.user_id = $1
       ORDER BY m.start_time DESC
       LIMIT $2 OFFSET $3`,
      [userId, limit, offset]
    );

    console.log(`Fetched ${result.rows.length} meetings for user ${userId}`);

    res.json({
      meetings: result.rows,
      pagination: {
        page,
        limit,
        total: totalCount,
        totalPages: Math.ceil(totalCount / limit),
      },
    });

  } catch (err) {
    console.error("GET ADMIN USER MEETINGS ERROR:", err);
    res.status(500).json({
      error: "GetAdminUserMeetingsFailed",
      message: err.message,
    });
  }
});

// ----------------------------------------------
// ADMIN: GET EXPENSE LOGS FOR A USER (PAGINATED)
// ----------------------------------------------
app.get("/admin/user-expenses/:userId", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const userId = req.params.userId;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;

    const totalResult = await pool.query(
      `SELECT COUNT(*) FROM trip_expenses WHERE user_id = $1`,
      [userId]
    );
    const total = parseInt(totalResult.rows[0].count);

    const logsResult = await pool.query(
      `SELECT 
         id,
         user_id AS "userId",
         start_location AS "startLocation",
         end_location AS "endLocation",
         travel_date AS "travelDate",
         distance_km AS "distanceKm",
         transport_mode AS "transportMode",
         amount_spent AS "amountSpent",
         currency,
         notes,
         receipt_urls AS "receiptUrls",
         client_id AS "clientId",
         created_at AS "createdAt",
         updated_at AS "updatedAt"
       FROM trip_expenses
       WHERE user_id = $1
       ORDER BY travel_date DESC
       LIMIT $2 OFFSET $3`,
      [userId, limit, offset]
    );

    res.json({
      expenses: logsResult.rows,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error("GET ADMIN USER EXPENSE LOGS ERROR:", err);
    res.status(500).json({ error: "GetAdminUserExpenseLogsFailed" });
  }
});




// Optional: Add a route to check admin status
app.get("/admin/check", authenticateToken, (req, res) => {
  res.json({ 
    isAdmin: req.user.isAdmin || false,
    userId: req.user.id,
    email: req.user.email
  });
});

// Optional: Debug route to verify token
app.get("/auth/verify", authenticateToken, (req, res) => {
  res.json({
    authenticated: true,
    user: {
      id: req.user.id,
      email: req.user.email,
      isAdmin: req.user.isAdmin || false
    }
  });
});




// ============================================
// TRIP EXPENSES ROUTES
// ============================================

app.post("/expenses", authenticateToken, async (req, res) => {
  try {
    const {
      start_location,
      end_location,
      travel_date,
      distance_km,
      transport_mode,
      amount_spent,
      currency = "₹",
      notes,
      receipt_urls,
      client_id
    } = req.body;

    const result = await pool.query(
      `INSERT INTO trip_expenses
      (user_id, start_location, end_location, travel_date, distance_km,
       transport_mode, amount_spent, currency, notes, receipt_urls, client_id)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      RETURNING *`,
      [
        req.user.id,
        start_location,
        end_location,
        travel_date,
        distance_km,
        transport_mode,
        amount_spent,
        currency,
        notes,
        receipt_urls || [],
        client_id || null
      ]
    );

    res.status(201).json({
      message: "Expense created successfully",
      expense: result.rows[0],
    });
  } catch (err) {
    console.error("CREATE EXPENSE ERROR:", err);
    res.status(500).json({ error: "CreateExpenseFailed" });
  }
});

app.get("/expenses/my-total", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT COALESCE(SUM(amount_spent), 0) as total_amount
       FROM trip_expenses
       WHERE user_id = $1`,
      [req.user.id]
    );

    res.json({
      totalAmount: parseFloat(result.rows[0].total_amount)
    });
  } catch (err) {
    console.error("GET TOTAL EXPENSE ERROR:", err);
    res.status(500).json({ error: "GetTotalExpenseFailed" });
  }
});

app.get("/expenses/my-expenses", authenticateToken, async (req, res) => {
  try {
    const { startDate, endDate, transportMode, clientId } = req.query;

    let query = `SELECT * FROM trip_expenses WHERE user_id = $1`;
    const params = [req.user.id];
    let count = 1;

    if (startDate) {
      count++;
      query += ` AND travel_date >= ${count}`;
      params.push(startDate);
    }
    if (endDate) {
      count++;
      query += ` AND travel_date <= ${count}`;
      params.push(endDate);
    }
    if (transportMode) {
      count++;
      query += ` AND transport_mode = ${count}`;
      params.push(transportMode);
    }
    if (clientId) {
      count++;
      query += ` AND client_id = ${count}`;
      params.push(clientId);
    }

    query += ` ORDER BY travel_date DESC`;

    const result = await pool.query(query, params);

    res.json({
      expenses: result.rows,
      total: result.rows.length,
      totalAmount: result.rows.reduce((sum, e) => sum + Number(e.amount_spent), 0),
    });
  } catch (err) {
    console.error("GET MY EXPENSES ERROR:", err);
    res.status(500).json({ error: "GetExpensesFailed" });
  }
});

app.post("/expenses/receipts", authenticateToken, async (req, res) => {
  try {
    const { imageData, fileName } = req.body;

    if (!imageData) {
      return res.status(400).json({ error: "ImageRequired" });
    }

    const buffer = Buffer.from(imageData, "base64");
    const randomName = `${Date.now()}-${fileName || "receipt.jpg"}`;
    const url = `https://storage.yourdomain.com/receipts/${randomName}`;

    console.log("Receipt upload simulated:", randomName);

    res.json({ url, fileName: randomName });
  } catch (err) {
    console.error("UPLOAD RECEIPT ERROR:", err);
    res.status(500).json({ error: "UploadReceiptFailed" });
  }
});

app.get("/expenses/:id", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM trip_expenses WHERE id = $1 AND user_id = $2`,
      [req.params.id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "ExpenseNotFound" });
    }

    res.json({ expense: result.rows[0] });
  } catch (err) {
    console.error("GET EXPENSE ERROR:", err);
    res.status(500).json({ error: "GetExpenseFailed" });
  }
});

app.put("/expenses/:id", authenticateToken, async (req, res) => {
  try {
    const {
      start_location,
      end_location,
      travel_date,
      distance_km,
      transport_mode,
      amount_spent,
      currency = "₹",
      notes,
      receipt_urls,
      client_id
    } = req.body;

    const result = await pool.query(
      `UPDATE trip_expenses
       SET start_location = $1,
           end_location = $2,
           travel_date = $3,
           distance_km = $4,
           transport_mode = $5,
           amount_spent = $6,
           currency = $7,
           notes = $8,
           receipt_urls = $9,
           client_id = $10,
           updated_at = NOW()
       WHERE id = $11 AND user_id = $12
       RETURNING *`,
      [
        start_location,
        end_location,
        travel_date,
        distance_km,
        transport_mode,
        amount_spent,
        currency,
        notes,
        receipt_urls || [],
        client_id || null,
        req.params.id,
        req.user.id
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "ExpenseNotFound" });
    }

    res.json({
      message: "Expense updated successfully",
      expense: result.rows[0],
    });
  } catch (err) {
    console.error("UPDATE EXPENSE ERROR:", err);
    res.status(500).json({ error: "UpdateExpenseFailed" });
  }
});

app.delete("/expenses/:id", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `DELETE FROM trip_expenses WHERE id = $1 AND user_id = $2 RETURNING id`,
      [req.params.id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "ExpenseNotFound" });
    }

    res.status(204).send();
  } catch (err) {
    console.error("DELETE EXPENSE ERROR:", err);
    res.status(500).json({ error: "DeleteExpenseFailed" });
  }
});


// ============================================
// MEETINGS ROUTES
// ============================================

// Start a new meeting
app.post("/meetings", authenticateToken, async (req, res) => {
  try {
    const { clientId, latitude, longitude, accuracy } = req.body;

    if (!clientId) {
      return res.status(400).json({ error: "ClientIdRequired" });
    }

    // Check if there's already an active meeting for this client
    const existingMeeting = await pool.query(
      `SELECT id FROM meetings 
       WHERE client_id = $1 
       AND user_id = $2 
       AND status = 'IN_PROGRESS'
       LIMIT 1`,
      [clientId, req.user.id]
    );

    if (existingMeeting.rows.length > 0) {
      return res.status(400).json({ 
        error: "ActiveMeetingExists",
        message: "You already have an active meeting with this client"
      });
    }

    const result = await pool.query(
      `INSERT INTO meetings 
       (user_id, client_id, start_time, start_latitude, start_longitude, start_accuracy, status)
       VALUES ($1, $2, NOW(), $3, $4, $5, 'IN_PROGRESS')
       RETURNING 
         id,
         user_id as "userId",
         client_id as "clientId",
         start_time as "startTime",
         end_time as "endTime",
         start_latitude as "startLatitude",
         start_longitude as "startLongitude",
         start_accuracy as "startAccuracy",
         end_latitude as "endLatitude",
         end_longitude as "endLongitude",
         end_accuracy as "endAccuracy",
         status,
         comments,
         attachments,
         created_at as "createdAt",
         updated_at as "updatedAt"`,
      [req.user.id, clientId, latitude || null, longitude || null, accuracy || null]
    );

    console.log(`✅ Meeting started: ${result.rows[0].id} for client ${clientId}`);

    res.status(201).json({
      message: "MeetingStarted",
      meeting: result.rows[0]
    });
  } catch (err) {
    console.error("START MEETING ERROR:", err);
    res.status(500).json({ error: "StartMeetingFailed" });
  }
});

// Get active meeting for a client
app.get("/meetings/active/:clientId", authenticateToken, async (req, res) => {
  try {
    const { clientId } = req.params;

    const result = await pool.query(
      `SELECT 
         id,
         user_id as "userId",
         client_id as "clientId",
         start_time as "startTime",
         end_time as "endTime",
         start_latitude as "startLatitude",
         start_longitude as "startLongitude",
         start_accuracy as "startAccuracy",
         end_latitude as "endLatitude",
         end_longitude as "endLongitude",
         end_accuracy as "endAccuracy",
         status,
         comments,
         attachments,
         created_at as "createdAt",
         updated_at as "updatedAt"
       FROM meetings
       WHERE client_id = $1 
       AND user_id = $2 
       AND status = 'IN_PROGRESS'
       ORDER BY start_time DESC
       LIMIT 1`,
      [clientId, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.json({ meeting: null });
    }

    res.json({ meeting: result.rows[0] });
  } catch (err) {
    console.error("GET ACTIVE MEETING ERROR:", err);
    res.status(500).json({ error: "GetActiveMeetingFailed" });
  }
});

// End/update a meeting
app.put("/meetings/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { endTime, status, comments, attachments, latitude, longitude, accuracy } = req.body;

    // Verify meeting belongs to user
    const checkResult = await pool.query(
      `SELECT id FROM meetings WHERE id = $1 AND user_id = $2`,
      [id, req.user.id]
    );

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: "MeetingNotFound" });
    }

    const result = await pool.query(
      `UPDATE meetings
       SET end_time = COALESCE($1, end_time, NOW()),
           end_latitude = COALESCE($2, end_latitude),
           end_longitude = COALESCE($3, end_longitude),
           end_accuracy = COALESCE($4, end_accuracy),
           status = COALESCE($5, status),
           comments = COALESCE($6, comments),
           attachments = COALESCE($7, attachments),
           updated_at = NOW()
       WHERE id = $8
       RETURNING 
         id,
         user_id as "userId",
         client_id as "clientId",
         start_time as "startTime",
         end_time as "endTime",
         start_latitude as "startLatitude",
         start_longitude as "startLongitude",
         start_accuracy as "startAccuracy",
         end_latitude as "endLatitude",
         end_longitude as "endLongitude",
         end_accuracy as "endAccuracy",
         status,
         comments,
         attachments,
         created_at as "createdAt",
         updated_at as "updatedAt"`,
      [
        endTime || null,
        latitude || null,
        longitude || null,
        accuracy || null,
        status || 'COMPLETED',
        comments || null,
        attachments ? JSON.stringify(attachments) : null,
        id
      ]
    );

    console.log(`✅ Meeting ended: ${id}`);

    res.json({
      message: "MeetingUpdated",
      meeting: result.rows[0]
    });
  } catch (err) {
    console.error("UPDATE MEETING ERROR:", err);
    res.status(500).json({ error: "UpdateMeetingFailed" });
  }
});

// Upload meeting attachment
app.post("/meetings/:id/attachments", authenticateToken, upload.single("file"), async (req, res) => {
  try {
    const { id } = req.params;

    if (!req.file) {
      return res.status(400).json({ error: "NoFileUploaded" });
    }

    // Verify meeting belongs to user
    const checkResult = await pool.query(
      `SELECT id FROM meetings WHERE id = $1 AND user_id = $2`,
      [id, req.user.id]
    );

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: "MeetingNotFound" });
    }

    // In production, upload to S3/Cloud Storage
    // For now, we'll simulate and return a mock URL
    const fileName = `${Date.now()}-${req.file.originalname}`;
    const fileUrl = `https://storage.yourdomain.com/meetings/${fileName}`;

    console.log(`📎 Meeting attachment uploaded: ${fileName} (${req.file.size} bytes)`);

    // Get current attachments
    const currentResult = await pool.query(
      `SELECT attachments FROM meetings WHERE id = $1`,
      [id]
    );

    const currentAttachments = currentResult.rows[0]?.attachments || [];
    const updatedAttachments = [...currentAttachments, fileUrl];

    // Update meeting with new attachment
    await pool.query(
      `UPDATE meetings 
       SET attachments = $1, updated_at = NOW()
       WHERE id = $2`,
      [JSON.stringify(updatedAttachments), id]
    );

    res.json({
      message: "AttachmentUploaded",
      url: fileUrl,
      fileName: fileName
    });
  } catch (err) {
    console.error("UPLOAD ATTACHMENT ERROR:", err);
    res.status(500).json({ error: "UploadAttachmentFailed" });
  }
});

// Get all meetings for a user (with optional filters)
app.get("/meetings", authenticateToken, async (req, res) => {
  try {
    const { clientId, status, startDate, endDate, page = 1, limit = 50 } = req.query;
    const offset = (page - 1) * limit;

    let query = `
      SELECT 
        m.id,
        m.user_id as "userId",
        m.client_id as "clientId",
        m.start_time as "startTime",
        m.end_time as "endTime",
        m.start_latitude as "startLatitude",
        m.start_longitude as "startLongitude",
        m.start_accuracy as "startAccuracy",
        m.end_latitude as "endLatitude",
        m.end_longitude as "endLongitude",
        m.end_accuracy as "endAccuracy",
        m.status,
        m.comments,
        m.attachments,
        m.created_at as "createdAt",
        m.updated_at as "updatedAt",
        c.name as "clientName",
        c.address as "clientAddress"
      FROM meetings m
      LEFT JOIN clients c ON m.client_id = c.id
      WHERE m.user_id = $1
    `;
    const params = [req.user.id];
    let paramCount = 1;

    if (clientId) {
      paramCount++;
      query += ` AND m.client_id = $${paramCount}`;
      params.push(clientId);
    }

    if (status) {
      paramCount++;
      query += ` AND m.status = $${paramCount}`;
      params.push(status);
    }

    if (startDate) {
      paramCount++;
      query += ` AND m.start_time >= $${paramCount}`;
      params.push(startDate);
    }

    if (endDate) {
      paramCount++;
      query += ` AND m.start_time <= $${paramCount}`;
      params.push(endDate);
    }

    query += ` ORDER BY m.start_time DESC LIMIT $${paramCount + 1} OFFSET $${paramCount + 2}`;
    params.push(limit, offset);

    const result = await pool.query(query, params);

    // Get total count
    let countQuery = "SELECT COUNT(*) FROM meetings WHERE user_id = $1";
    const countParams = [req.user.id];
    const countResult = await pool.query(countQuery, countParams);
    const total = parseInt(countResult.rows[0].count);

    res.json({
      meetings: result.rows,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: total,
        totalPages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error("GET MEETINGS ERROR:", err);
    res.status(500).json({ error: "GetMeetingsFailed" });
  }
});

// Get single meeting by ID
app.get("/meetings/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `SELECT 
         m.id,
         m.user_id as "userId",
         m.client_id as "clientId",
         m.start_time as "startTime",
         m.end_time as "endTime",
         m.start_latitude as "startLatitude",
         m.start_longitude as "startLongitude",
         m.start_accuracy as "startAccuracy",
         m.end_latitude as "endLatitude",
         m.end_longitude as "endLongitude",
         m.end_accuracy as "endAccuracy",
         m.status,
         m.comments,
         m.attachments,
         m.created_at as "createdAt",
         m.updated_at as "updatedAt",
         c.name as "clientName",
         c.email as "clientEmail",
         c.phone as "clientPhone",
         c.address as "clientAddress"
       FROM meetings m
       LEFT JOIN clients c ON m.client_id = c.id
       WHERE m.id = $1 AND m.user_id = $2`,
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "MeetingNotFound" });
    }

    res.json({ meeting: result.rows[0] });
  } catch (err) {
    console.error("GET MEETING ERROR:", err);
    res.status(500).json({ error: "GetMeetingFailed" });
  }
});

// Delete a meeting (optional - might want to soft delete instead)
app.delete("/meetings/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `DELETE FROM meetings 
       WHERE id = $1 AND user_id = $2 
       RETURNING id`,
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "MeetingNotFound" });
    }

    console.log(`🗑️ Meeting deleted: ${id}`);

    res.json({ message: "MeetingDeleted" });
  } catch (err) {
    console.error("DELETE MEETING ERROR:", err);
    res.status(500).json({ error: "DeleteMeetingFailed" });
  }
});

// ==========================
// GET USER EXPENSES (Paginated)
// ==========================
app.get("/admin/user-expenses/:userId", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const userId = req.params.userId;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;

    // Count total expenses
    const totalCount = await pool.query(
      `SELECT COUNT(*) FROM trip_expenses WHERE user_id = $1`,
      [userId]
    );

    // Fetch expenses - EXACT column names from your schema
    const result = await pool.query(
      `SELECT
        id,
        user_id as "userId",
        start_location as "startLocation",
        end_location as "endLocation",
        travel_date as "travelDate",
        distance_km as "distanceKm",
        transport_mode as "transportMode",
        amount_spent as "amountSpent",
        currency,
        notes,
        receipt_urls as "receiptUrls",
        client_id as "clientId",
        created_at as "createdAt",
        updated_at as "updatedAt"
       FROM trip_expenses
       WHERE user_id = $1
       ORDER BY travel_date DESC
       LIMIT $2 OFFSET $3`,
      [userId, limit, offset]
    );
    res.json({
      expenses: result.rows,
      pagination: {
        page,
        limit,
        total: Number(totalCount.rows[0].count),
        totalPages: Math.ceil(Number(totalCount.rows[0].count) / limit)
      }
    });

  } catch (err) {
    console.error("GET USER EXPENSES ERROR:", err);
    res.status(500).json({ error: "GetUserExpensesFailed", message: err.message });
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

// ============================================
// START SERVER
// ============================================

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📍 Pincode-based filtering enabled`);
});
