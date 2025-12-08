import pkg from "pg";
const { Pool } = pkg;
import dotenv from "dotenv";

dotenv.config();

// Render provides DATABASE_URL as a single connection string
// For local development, it will use individual variables
const connectionString = process.env.DATABASE_URL;

export const pool = new Pool(
  connectionString
    ? {
        // PRODUCTION (Render) - Use DATABASE_URL
        connectionString: connectionString,
        ssl: {
          rejectUnauthorized: false
        }
      }
    : {
        // LOCAL DEVELOPMENT - Use individual variables
        user: process.env.DB_USER || "postgres",
        host: process.env.DB_HOST || "localhost",
        database: process.env.DB_NAME || "client_tracking_app",
        password: process.env.DB_PASSWORD || "root",
        port: process.env.DB_PORT || 5432,
      }
);

// Handle pool errors
pool.on("error", (err, client) => {
  console.error("Unexpected error on idle client", err);
  process.exit(-1);
});

export default pool;