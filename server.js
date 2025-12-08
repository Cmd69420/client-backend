import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import xlsx from "xlsx";
import multer from "multer";
import { pool } from "./db.js";

const app = express();
app.use(cors({
  origin: "*",                                      // or your specific dashboard URL
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

// Handle preflight requests
app.options("*", cors());
app.use(express.json());


const JWT_SECRET = process.env.JWT_SECRET || "your-super-secret-jwt-key-change-in-production";
const PORT = process.env.PORT || 5000;

// Test DB connection
pool.query("SELECT NOW()", (err, res) => {
  if (err) {
    console.error("âŒ Database connection failed:", err);
  } else {
    console.log("âœ… Database connected successfully");
  }
});


const upload = multer({ storage: multer.memoryStorage() });
// ============================================
// HELPER FUNCTIONS
// ============================================

// Convert GPS coordinates to pincode using reverse geocoding
// Add at top with other constants
const GOOGLE_MAPS_API_KEY = process.env.GOOGLE_MAPS_API_KEY; // Get from Google Cloud Console

// Replace the function
const getPincodeFromCoordinates = async (latitude, longitude) => {
  try {
    const response = await fetch(
      `https://maps.googleapis.com/maps/api/geocode/json?latlng=${latitude},${longitude}&key=${GOOGLE_MAPS_API_KEY}`
    );
    
    const data = await response.json();
    
    if (data.status === 'OK' && data.results.length > 0) {
      const addressComponents = data.results[0].address_components;
      const pincodeComponent = addressComponents.find(
        component => component.types.includes('postal_code')
      );
      
      const pincode = pincodeComponent?.long_name || null;
      console.log(`ðŸ“ Google: (${latitude}, ${longitude}) â†’ Pincode: ${pincode}`);
      return pincode;
    }
    
    console.log(`âš ï¸ Google API returned: ${data.status}`);
    return null;
  } catch (error) {
    console.error("âŒ Google Geocoding error:", error);
    return null;
  }
};

// Get user's current pincode from their latest location log
async function getCoordinatesFromPincode(pincode) {
  try {
    const url = `https://maps.googleapis.com/maps/api/geocode/json?address=${pincode}&key=${GOOGLE_MAPS_API_KEY}`;
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
  console.log(`ðŸ“¥ ${req.method} ${req.path}`);
  next();
});
// Verify JWT Token
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

console.log("ðŸ”§ Registering routes...");

const requireAdmin = (req, res, next) => {
  if (!req.user || !req.user.isAdmin) {
    return res.status(403).json({ error: "AdminOnly" });
  }
  next();
};
// ============================================
// FIXED: Proper type casting for PostgreSQL
// ============================================

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
        const phone = row.phone || row.Phone || null;
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
        }

        if (!name || !address) {
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
            }
          } catch (err) {
            console.log(`⚠️ Geocoding failed for address`);
          }
        }

        // ============================================
        // SIMPLIFIED DUPLICATE CHECK WITH EXPLICIT TYPES
        // ============================================
        
        // Option 1: Check by email first (most reliable)
        let duplicateCheck = { rows: [] };
        
        if (email) {
          duplicateCheck = await client.query(
            `SELECT id FROM clients WHERE LOWER(TRIM(email)) = LOWER(TRIM($1)) LIMIT 1`,
            [email]
          );
        }
        
        // Option 2: Check by phone if no email match
        if (duplicateCheck.rows.length === 0 && phone) {
          const cleanPhone = phone.replace(/\D/g, ''); // Remove non-digits
          duplicateCheck = await client.query(
            `SELECT id FROM clients 
             WHERE REGEXP_REPLACE(phone, '\\D', '', 'g') = $1 
             LIMIT 1`,
            [cleanPhone]
          );
        }
        
        // Option 3: Check by name + pincode if still no match
        if (duplicateCheck.rows.length === 0) {
          const cleanName = name.toLowerCase().trim().replace(/[^a-z0-9\s]/g, '');
          
          if (pincode) {
            duplicateCheck = await client.query(
              `SELECT id FROM clients 
               WHERE LOWER(TRIM(REGEXP_REPLACE(name, '[^a-zA-Z0-9\\s]', '', 'g'))) = $1 
               AND pincode = $2
               LIMIT 1`,
              [cleanName, pincode]
            );
          } else {
            duplicateCheck = await client.query(
              `SELECT id FROM clients 
               WHERE LOWER(TRIM(REGEXP_REPLACE(name, '[^a-zA-Z0-9\\s]', '', 'g'))) = $1
               LIMIT 1`,
              [cleanName]
            );
          }
        }

        if (duplicateCheck.rows.length > 0) {
          // DUPLICATE FOUND - Update
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
             WHERE id = $9`,
            [
              email,
              phone,
              address,
              latitude,
              longitude,
              pincode,
              note,
              status,
              existingId
            ]
          );

          updated++;
          console.log(`🔄 Updated: ${name} (ID: ${existingId})`);
        } else {
          // NO DUPLICATE - Insert new
          await client.query(
            `INSERT INTO clients
             (name, email, phone, address, latitude, longitude, status, notes, created_by, source, pincode)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
            [
              name,
              email,
              phone,
              address,
              latitude,
              longitude,
              status,
              note,
              req.user.id,
              source,
              pincode
            ]
          );

          imported++;
          console.log(`✅ Imported: ${name}`);
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
      res.status(500).json({ 
        error: "UploadFailed", 
        message: error.message 
      });
    } finally {
      client.release();
    }
  }
);

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

    const token = jwt.sign(
  {
    id: user.id,
    email: user.email,
    isAdmin: user.is_admin   // <— REQUIRED
  },
  JWT_SECRET,
  { expiresIn: "7d" }
);

  // Save token to server sessions table
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




// REGISTER — used by mobile app
// REGISTER – used by mobile app
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

    // Optional profile row
    await pool.query(
      `INSERT INTO profiles (user_id) VALUES ($1)`,
      [user.id]
    );

    // Issue JWT immediately
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        isAdmin: false
      },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    // ✅ FIX: Save token to user_sessions table (same as login)
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

    console.log("ðŸ”‘ Password Reset Token:", resetToken);
    console.log("ðŸ“§ For Email:", email);

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

    console.log(`âœ… Client created: ${name} (Pincode: ${pincode || 'N/A'})`);

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

    console.log(`ðŸ” Fetching clients for user: ${req.user.id}`);

    // Get user's current pincode from their latest location log
    const userPincode = (await pool.query("SELECT pincode FROM users WHERE id = $1", [req.user.id])).rows[0]?.pincode;
    if (!userPincode) {
      return res.status(400).json({ 
        error: "NoPincodeFound",
        message: "Please enable location tracking first. No location data available."
      });
    }

    console.log(`ðŸ“ Filtering clients by pincode: ${userPincode}`);

    // Build query - FILTER BY PINCODE
   let query = `
  SELECT *
  FROM clients
  WHERE pincode = $1
  AND (created_by IS NULL OR created_by = $2)
`;
const params = [userPincode, req.user.id];
let paramCount = 2;


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

    console.log(`âœ… Found ${result.rows.length} clients in pincode ${userPincode}`);

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
    const { latitude, longitude, accuracy, activity, notes, battery } = req.body;


    if (!latitude || !longitude) {
      return res.status(400).json({ error: "LocationRequired" });
    }

    console.log(`ðŸ“ Logging location for user ${req.user.id}: ${latitude}, ${longitude}`);

    // Get pincode from coordinates
    const pincode = await getPincodeFromCoordinates(latitude, longitude);

    const result = await pool.query(
      `INSERT INTO location_logs (user_id, latitude, longitude, accuracy, activity, notes, pincode, battery)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING *
`,
      [req.user.id, latitude, longitude, accuracy || null, activity || null, notes || null, pincode, battery || null
]

    );

    // 🔄 update user's pincode based on latest location
    if (pincode) {
      await pool.query(
        `UPDATE users SET pincode = $1 WHERE id = $2 AND pincode IS DISTINCT FROM $1`,
        [pincode, req.user.id]
      );
      console.log(`📍 Updated user pincode to ${pincode} for user ${req.user.id}`);
    }


    await pool.query(
                 `UPDATE users
                  SET pincode = $1
                  WHERE id = $2 AND pincode IS NULL`,
    [pincode, req.user.id]
);

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

    console.log(`âœ… Location logged with pincode: ${pincode}`);

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


// ============================================
// DUPLICATE DETECTION & CLEANUP
// ============================================

// Helper function to detect and remove duplicates
const removeDuplicateClients = async (client) => {
  try {
    // Strategy: Find duplicates based on:
    // 1. Same name (case-insensitive, ignore special characters)
    // 2. OR same email
    // 3. OR same phone
    // 4. OR same location (within 100 meters)

    const cleanName = (name) => {
      return name
        .toLowerCase()
        .replace(/[^a-z0-9\s]/g, '') // Remove special chars like â€“ vs -
        .replace(/\s+/g, ' ')
        .trim();
    };

    const duplicateQuery = `
      SELECT id, name, email, phone, latitude, longitude, pincode, created_at
      FROM clients
      WHERE (
        -- Same name (cleaned)
        LOWER(REGEXP_REPLACE(name, '[^a-zA-Z0-9\\s]', '', 'g')) = $1
        
        -- OR same email
        ${client.email ? 'OR email = $2' : ''}
        
        -- OR same phone
        ${client.phone ? 'OR phone = $3' : ''}
        
        -- OR same location (within ~100 meters)
        ${client.latitude && client.longitude ? `
          OR (
            latitude IS NOT NULL 
            AND longitude IS NOT NULL
            AND (6371000 * acos(
              cos(radians($4)) * cos(radians(latitude)) * 
              cos(radians(longitude) - radians($5)) + 
              sin(radians($4)) * sin(radians(latitude))
            )) <= 100
          )
        ` : ''}
      )
      ORDER BY created_at ASC
    `;

    const params = [cleanName(client.name)];
    if (client.email) params.push(client.email);
    if (client.phone) params.push(client.phone);
    if (client.latitude && client.longitude) {
      params.push(client.latitude, client.longitude);
    }

    const result = await pool.query(duplicateQuery, params);

    if (result.rows.length > 1) {
      console.log(`ðŸ” Found ${result.rows.length} duplicates for: ${client.name}`);
      
      // Keep the newest one (most recent data), delete older ones
      const newest = result.rows[result.rows.length - 1];
      const oldOnes = result.rows.slice(0, -1);
      
      for (const old of oldOnes) {
        await pool.query('DELETE FROM clients WHERE id = $1', [old.id]);
        console.log(`ðŸ—‘ï¸  Deleted duplicate: ${old.name} (${old.id}) - Pincode: ${old.pincode}`);
      }
      
      return {
        duplicatesRemoved: oldOnes.length,
        keptClientId: newest.id
      };
    }

    return { duplicatesRemoved: 0, keptClientId: null };
  } catch (error) {
    console.error('Error removing duplicates:', error);
    return { duplicatesRemoved: 0, keptClientId: null };
  }
};




// ============================================
// TALLY SYNC ROUTES
// ============================================

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

// SYNC CLIENTS FROM TALLY
app.post("/api/sync/tally-clients", authenticateMiddleware, async (req, res) => {
  const client = await pool.connect();
  
  try {
    const { clients: tallyClients } = req.body;

    if (!tallyClients || !Array.isArray(tallyClients)) {
      return res.status(400).json({ error: "InvalidPayload", message: "Expected array of clients" });
    }

    console.log(`ðŸ“¥ Tally sync started: ${tallyClients.length} clients received`);

    await client.query("BEGIN");

    let newCount = 0;
    let updatedCount = 0;
    let failedCount = 0;
    const errors = [];

    let duplicatesRemovedTotal = 0;

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
      notes
    } = tallyClient;

    if (!name) {
      failedCount++;
      errors.push({ tally_guid, error: "Missing name" });
      continue;
    }

    // Auto-calculate pincode if lat/lng provided
    let finalPincode = pincode || null;
    if (!finalPincode && latitude && longitude) {
      finalPincode = await getPincodeFromCoordinates(latitude, longitude);
    }

    // ðŸ†• STEP 1: Check and remove duplicates BEFORE inserting/updating
    // ============================================
// IMPROVED DUPLICATE DETECTION & CLEANUP
// ============================================

/**
 * Smart duplicate detection that's more conservative
 * Only marks as duplicate if there's HIGH confidence
 */
const findDuplicates = async (client) => {
  try {
    const duplicates = [];
    
    // Strategy 1: EXACT GUID match (100% duplicate)
    if (client.tally_guid) {
      const guidResult = await pool.query(
        `SELECT * FROM clients WHERE tally_guid = $1`,
        [client.tally_guid]
      );
      if (guidResult.rows.length > 0) {
        return guidResult.rows;
      }
    }

    // Strategy 2: EXACT email + EXACT phone (very high confidence)
    if (client.email && client.phone) {
      const exactResult = await pool.query(
        `SELECT * FROM clients 
         WHERE LOWER(TRIM(email)) = LOWER(TRIM($1)) 
         AND phone = $2`,
        [client.email, client.phone]
      );
      if (exactResult.rows.length > 0) {
        return exactResult.rows;
      }
    }

    // Strategy 3: EXACT name + EXACT pincode (high confidence for same area)
    if (client.name && client.pincode) {
      const nameResult = await pool.query(
        `SELECT * FROM clients 
         WHERE LOWER(TRIM(REGEXP_REPLACE(name, '[^a-zA-Z0-9\\s]', '', 'g'))) = 
               LOWER(TRIM(REGEXP_REPLACE($1, '[^a-zA-Z0-9\\s]', '', 'g')))
         AND pincode = $2`,
        [client.name, client.pincode]
      );
      if (nameResult.rows.length > 0) {
        return nameResult.rows;
      }
    }

    // Strategy 4: EXACT coordinates (within 10 meters - same building)
    if (client.latitude && client.longitude) {
      const locationResult = await pool.query(
        `SELECT * FROM clients 
         WHERE latitude IS NOT NULL 
         AND longitude IS NOT NULL
         AND (6371000 * acos(
           cos(radians($1)) * cos(radians(latitude)) * 
           cos(radians(longitude) - radians($2)) + 
           sin(radians($1)) * sin(radians(latitude))
         )) <= 10`,
        [client.latitude, client.longitude]
      );
      if (locationResult.rows.length > 0) {
        return locationResult.rows;
      }
    }

    return duplicates;

  } catch (error) {
    console.error('Error finding duplicates:', error);
    return [];
  }
};

/**
 * Score clients based on data completeness
 * Higher score = more complete data = keep this one
 */
const scoreClient = (client) => {
  let score = 0;
  
  if (client.name) score += 10;
  if (client.email && client.email.includes('@')) score += 15;
  if (client.phone && client.phone.length >= 10) score += 15;
  if (client.address && client.address.length > 10) score += 10;
  if (client.pincode && client.pincode.length === 6) score += 10;
  if (client.latitude && client.longitude) score += 10;
  if (client.notes && client.notes.length > 0) score += 5;
  if (client.tally_guid) score += 20; // Tally GUID is valuable
  
  // Bonus for recent data
  if (client.updated_at) {
    const daysSinceUpdate = (Date.now() - new Date(client.updated_at)) / (1000 * 60 * 60 * 24);
    if (daysSinceUpdate < 30) score += 5;
  }
  
  return score;
};

/**
 * Merge data from multiple duplicate records
 * Takes the best field from each duplicate
 */
const mergeDuplicateData = (duplicates) => {
  const merged = { ...duplicates[0] };
  
  for (const dup of duplicates) {
    // Use the most complete email
    if (!merged.email && dup.email) merged.email = dup.email;
    if (dup.email && dup.email.includes('@') && (!merged.email || !merged.email.includes('@'))) {
      merged.email = dup.email;
    }
    
    // Use the longest phone number
    if (!merged.phone && dup.phone) merged.phone = dup.phone;
    if (dup.phone && dup.phone.length > (merged.phone?.length || 0)) {
      merged.phone = dup.phone;
    }
    
    // Use the longest address
    if (!merged.address && dup.address) merged.address = dup.address;
    if (dup.address && dup.address.length > (merged.address?.length || 0)) {
      merged.address = dup.address;
    }
    
    // Prefer pincode from Tally
    if (!merged.pincode && dup.pincode) merged.pincode = dup.pincode;
    
    // Prefer coordinates that exist
    if (!merged.latitude && dup.latitude) merged.latitude = dup.latitude;
    if (!merged.longitude && dup.longitude) merged.longitude = dup.longitude;
    
    // Keep Tally GUID if available
    if (!merged.tally_guid && dup.tally_guid) merged.tally_guid = dup.tally_guid;
    
    // Combine notes
    if (dup.notes && dup.notes !== merged.notes) {
      merged.notes = merged.notes ? `${merged.notes}; ${dup.notes}` : dup.notes;
    }
  }
  
  return merged;
};

/**
 * Remove duplicates intelligently
 * Returns: { duplicatesRemoved: number, keptClientId: string }
 */
const removeDuplicateClients = async (client) => {
  try {
    const duplicates = await findDuplicates(client);
    
    if (duplicates.length <= 1) {
      return { duplicatesRemoved: 0, keptClientId: null };
    }

    console.log(`🔍 Found ${duplicates.length} potential duplicates for: ${client.name}`);
    
    // Score each duplicate
    const scoredDuplicates = duplicates.map(dup => ({
      ...dup,
      score: scoreClient(dup)
    }));
    
    // Sort by score (highest first)
    scoredDuplicates.sort((a, b) => b.score - a.score);
    
    // Keep the one with highest score
    const keepClient = scoredDuplicates[0];
    const deleteClients = scoredDuplicates.slice(1);
    
    console.log(`📊 Scores: Keep ${keepClient.name} (${keepClient.score} pts), Delete ${deleteClients.length} others`);
    
    // Merge the best data from all duplicates
    const mergedData = mergeDuplicateData(scoredDuplicates);
    
    // Update the kept client with merged data
    await pool.query(
      `UPDATE clients 
       SET email = $1, phone = $2, address = $3, pincode = $4,
           latitude = $5, longitude = $6, notes = $7, tally_guid = $8,
           updated_at = NOW()
       WHERE id = $9`,
      [
        mergedData.email,
        mergedData.phone,
        mergedData.address,
        mergedData.pincode,
        mergedData.latitude,
        mergedData.longitude,
        mergedData.notes,
        mergedData.tally_guid,
        keepClient.id
      ]
    );
    
    console.log(`✅ Merged best data into: ${keepClient.name} (${keepClient.id})`);
    
    // Delete the duplicates
    for (const dup of deleteClients) {
      await pool.query('DELETE FROM clients WHERE id = $1', [dup.id]);
      console.log(`🗑️ Deleted duplicate: ${dup.name} (${dup.id}) - Score: ${dup.score}`);
    }
    
    return {
      duplicatesRemoved: deleteClients.length,
      keptClientId: keepClient.id
    };

  } catch (error) {
    console.error('Error removing duplicates:', error);
    return { duplicatesRemoved: 0, keptClientId: null };
  }
};

// ============================================
// OPTIONAL: Manual Duplicate Cleanup Route
// ============================================

/**
 * Run full duplicate cleanup across entire database
 * Use this carefully!
 */
app.post("/api/sync/cleanup-duplicates", authenticateMiddleware, async (req, res) => {
  const client = await pool.connect();
  
  try {
    await client.query("BEGIN");
    
    // Get all clients
    const allClients = await client.query("SELECT * FROM clients ORDER BY created_at ASC");
    
    let totalRemoved = 0;
    const processed = new Set();
    
    for (const currentClient of allClients.rows) {
      // Skip if already processed as part of another duplicate group
      if (processed.has(currentClient.id)) continue;
      
      const result = await removeDuplicateClients(currentClient);
      totalRemoved += result.duplicatesRemoved;
      
      // Mark all related duplicates as processed
      if (result.keptClientId) {
        processed.add(result.keptClientId);
      }
    }
    
    await client.query("COMMIT");
    
    res.json({
      message: "DuplicateCleanupCompleted",
      duplicatesRemoved: totalRemoved,
      totalProcessed: allClients.rows.length
    });
    
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("CLEANUP ERROR:", err);
    res.status(500).json({ error: "CleanupFailed", message: err.message });
  } finally {
    client.release();
  }
});

    let existingClient = null;
    
    // Check Tally mapping
    if (tally_guid) {
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
    
    // Fallback: Check by email
    if (!existingClient && email) {
      const emailResult = await client.query(
        "SELECT * FROM clients WHERE email = $1 LIMIT 1",
        [email]
      );
      if (emailResult.rows.length > 0) {
        existingClient = emailResult.rows[0];
      }
    }

    // Fallback: Check by phone
    if (!existingClient && phone) {
      const phoneResult = await client.query(
        "SELECT * FROM clients WHERE phone = $1 LIMIT 1",
        [phone]
      );
      if (phoneResult.rows.length > 0) {
        existingClient = phoneResult.rows[0];
      }
    }

    let clientId;

    if (existingClient) {
      // UPDATE existing client
      const updateResult = await client.query(
        `UPDATE clients 
         SET name = $1, email = $2, phone = $3, address = $4, 
             latitude = $5, longitude = $6, status = $7, notes = $8, pincode = $9,
             updated_at = NOW()
         WHERE id = $10
         RETURNING id`,
        [name, email, phone, address, latitude, longitude, status, notes, pincode, existingClient.id]
      );
      
      clientId = updateResult.rows[0].id;
      updatedCount++;
      console.log(`âœï¸  Updated: ${name} (${clientId}) - Pincode: ${pincode || 'N/A'}`);
    } else {
      // INSERT new client
      const insertResult = await client.query(
        `INSERT INTO clients 
         (name, email, phone, address, latitude, longitude, status, notes, pincode, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL)
         RETURNING id`,
        [name, email, phone, address, latitude, longitude, status, notes, pincode]
      );
      
      clientId = insertResult.rows[0].id;
      newCount++;
      console.log(`âœ¨ Created: ${name} (${clientId}) - Pincode: ${pincode || 'N/A'}`);
    }

    // Update Tally mapping
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
    console.error(`âŒ Failed to sync client: ${tallyClient.name}`, error.message);
  }
}
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

    await client.query("COMMIT");

    // Update this part at the end of the sync route:
    console.log(`âœ… Tally sync completed: ${newCount} new, ${updatedCount} updated, ${failedCount} failed, ${duplicatesRemovedTotal} duplicates removed`);

    res.status(200).json({
    message: "SyncCompleted",
    summary: {
        total: tallyClients.length,
        new: newCount,
        updated: updatedCount,
        failed: failedCount,
        duplicatesRemoved: duplicatesRemovedTotal  // ðŸ†• Add this
    },
    errors: errors.length > 0 ? errors : undefined
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("TALLY SYNC ERROR:", err);
    
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

// GET SYNC STATUS
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

// GET LATEST SYNC INFO
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

// MANUAL TRIGGER SYNC
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
// ADMIN ROUTES - Get ALL data (no filtering)
// ============================================

// GET ALL CLIENTS (ADMIN - No pincode filter)
app.get("/admin/clients", authenticateToken, async (req, res) => {
  try {
    const { status, search, page = 1, limit = 1000 } = req.query;
    const offset = (page - 1) * limit;

    console.log(`📊 Admin fetching ALL clients`);

    // Build query - NO PINCODE FILTER
    let query = "SELECT * FROM clients WHERE 1=1";
    const params = [];
    let paramCount = 0;

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
    let countQuery = "SELECT COUNT(*) FROM clients WHERE 1=1";
    const countParams = [];
    let countParamIndex = 0;

    if (status) {
      countParamIndex++;
      countQuery += ` AND status = $${countParamIndex}`;
      countParams.push(status);
    }

    const countResult = await pool.query(countQuery, countParams);
    const total = parseInt(countResult.rows[0].count);

    console.log(`✅ Admin found ${result.rows.length} clients (total: ${total})`);

    res.json({
      clients: result.rows,
      isAdmin: true,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: total,
        totalPages: Math.ceil(total / limit),
      },
    });
  } catch (err) {
    console.error("GET ADMIN CLIENTS ERROR:", err);
    res.status(500).json({ error: "GetAdminClientsFailed" });
  }
});

// GET ALL USERS (ADMIN)
app.get("/admin/users", authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 100 } = req.query;
    const offset = (page - 1) * limit;

    console.log(`📊 Admin fetching ALL users`);

    const result = await pool.query(
      `SELECT u.id, u.email, u.created_at, u.pincode,
              p.full_name, p.department, p.work_hours_start, p.work_hours_end
       FROM users u
       LEFT JOIN profiles p ON u.id = p.user_id
       ORDER BY u.created_at DESC
       LIMIT $1 OFFSET $2`,
      [limit, offset]
    );

    const countResult = await pool.query("SELECT COUNT(*) FROM users");
    const total = parseInt(countResult.rows[0].count);

    console.log(`✅ Admin found ${result.rows.length} users (total: ${total})`);

    res.json({
      users: result.rows,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: total,
        totalPages: Math.ceil(total / limit),
      },
    });
  } catch (err) {
    console.error("GET ADMIN USERS ERROR:", err);
    res.status(500).json({ error: "GetAdminUsersFailed" });
  }
});

// GET ADMIN ANALYTICS (ALL data)
app.get("/admin/analytics", authenticateToken, async (req, res) => {
  try {
    console.log(`📊 Admin fetching analytics`);

    // Get client stats
    const clientStats = await pool.query(`
      SELECT 
        COUNT(*) as total_clients,
        COUNT(CASE WHEN status = 'active' THEN 1 END) as active_clients,
        COUNT(CASE WHEN latitude IS NOT NULL AND longitude IS NOT NULL THEN 1 END) as clients_with_location,
        COUNT(DISTINCT pincode) as unique_pincodes
      FROM clients
    `);

    // Get user stats
    const userStats = await pool.query(`
      SELECT COUNT(*) as total_users
      FROM users
    `);

    // Get location logs count
    const locationStats = await pool.query(`
      SELECT COUNT(*) as total_logs
      FROM location_logs
    `);

    res.json({
      clients: clientStats.rows[0],
      users: userStats.rows[0],
      locations: locationStats.rows[0],
    });
  } catch (err) {
    console.error("GET ADMIN ANALYTICS ERROR:", err);
    res.status(500).json({ error: "GetAdminAnalyticsFailed" });
  }
});

// Add this near the end of server.js, before app.listen()

// ============================================
// ADMIN ROUTES - Get ALL data (no filtering)
// ============================================

// GET ALL CLIENTS (ADMIN - No pincode filter)
app.get("/admin/clients", authenticateToken, async (req, res) => {
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

    res.json({
      clients: result.rows,
      pagination: { page: parseInt(page), limit: parseInt(limit), total, totalPages: Math.ceil(total / limit) }
    });
  } catch (err) {
    console.error("ADMIN CLIENTS ERROR:", err);
    res.status(500).json({ error: "GetAdminClientsFailed" });
  }
});

// GET ALL USERS (ADMIN)
app.get("/admin/users", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.email, u.created_at, u.pincode,
              p.full_name, p.department, p.work_hours_start, p.work_hours_end
       FROM users u
       LEFT JOIN profiles p ON u.id = p.user_id
       ORDER BY u.created_at DESC`
    );

    res.json({ users: result.rows });
  } catch (err) {
    console.error("ADMIN USERS ERROR:", err);
    res.status(500).json({ error: "GetAdminUsersFailed" });
  }
});

// GET ADMIN ANALYTICS
app.get("/admin/analytics", authenticateToken, async (req, res) => {
  try {
    const clientStats = await pool.query(`
      SELECT 
        COUNT(*) as total_clients,
        COUNT(CASE WHEN status = 'active' THEN 1 END) as active_clients,
        COUNT(CASE WHEN latitude IS NOT NULL THEN 1 END) as clients_with_location,
        COUNT(DISTINCT pincode) as unique_pincodes
      FROM clients
    `);

    const userStats = await pool.query(`SELECT COUNT(*) as total_users FROM users`);
    const locationStats = await pool.query(`SELECT COUNT(*) as total_logs FROM location_logs`);

    res.json({
      clients: clientStats.rows[0],
      users: userStats.rows[0],
      locations: locationStats.rows[0]
    });
  } catch (err) {
    console.error("ADMIN ANALYTICS ERROR:", err);
    res.status(500).json({ error: "GetAdminAnalyticsFailed" });
  }
});

app.get("/admin/location-logs/:userId", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 200 } = req.query;
    const offset = (page - 1) * limit;
    const userId = req.params.userId;

    const result = await pool.query(
      `SELECT id, latitude, longitude, accuracy, activity,battery, notes, pincode, timestamp
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
    res.status(500).json({ error: "GetAdminLocationLogsFailed" });
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

// Get logged-in user's expenses
app.get("/expenses/my-expenses", authenticateToken, async (req, res) => {
  try {
    const { startDate, endDate, transportMode, clientId } = req.query;

    let query = `SELECT * FROM trip_expenses WHERE user_id = $1`;
    const params = [req.user.id];
    let count = 1;

    if (startDate) {
      count++;
      query += ` AND travel_date >= $${count}`;
      params.push(startDate);
    }
    if (endDate) {
      count++;
      query += ` AND travel_date <= $${count}`;
      params.push(endDate);
    }
    if (transportMode) {
      count++;
      query += ` AND transport_mode = $${count}`;
      params.push(transportMode);
    }
    if (clientId) {
      count++;
      query += ` AND client_id = $${count}`;
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

// Get expense by ID
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

// Update expense
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

// Delete expense
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

// Upload receipt as base64 → returns URL
app.post("/expenses/receipts", authenticateToken, async (req, res) => {
  try {
    const { imageData, fileName } = req.body;

    if (!imageData) {
      return res.status(400).json({ error: "ImageRequired" });
    }

    // In production, upload to S3 / Cloudinary / Firebase
    const buffer = Buffer.from(imageData, "base64");
    const randomName = `${Date.now()}-${fileName || "receipt.jpg"}`;
    const url = `https://storage.yourdomain.com/receipts/${randomName}`;

    // TODO: Implement actual upload here
    console.log("Receipt upload simulated:", randomName);

    res.json({ url, fileName: randomName });
  } catch (err) {
    console.error("UPLOAD RECEIPT ERROR:", err);
    res.status(500).json({ error: "UploadReceiptFailed" });
  }
});


app.get("/expenses/my-total", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT COALESCE(SUM(amount_spent), 0) AS total_amount FROM trip_expenses WHERE user_id = $1",
      [req.user.id]
    );

    res.json({
      totalAmount: Number(result.rows[0].total_amount)
    });
  } catch (err) {
    console.error("GET TOTAL EXPENSE ERROR:", err);
    res.status(500).json({ error: "GetTotalExpenseFailed" });
  }
});




// Start server
app.listen(PORT, () => {
  console.log(`ðŸš€ Server running on http://localhost:${PORT}`);
  console.log(`ðŸ“ Pincode-based filtering enabled`);
});
