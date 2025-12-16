// ============================================
// ROBUST GEOCODING WITH MULTIPLE FALLBACKS
// Replace utils/geocodeBatch.js with this improved version
// ============================================

import { pool } from "../db.js";

/**
 * Background job to geocode clients missing location data
 * Uses multiple strategies to maximize success rate
 */
export async function startBackgroundGeocode() {
  console.log("🌍 Starting intelligent background geocoding...");
  
  geocodeClientsInBackground().catch(err => {
    console.error("❌ Background geocoding job failed:", err);
  });
}

async function geocodeClientsInBackground() {
  const startTime = Date.now();
  let processed = 0;
  let updated = 0;
  let failed = 0;
  const failures = [];

  try {
    // Find clients missing lat/lon
    const result = await pool.query(`
      SELECT id, name, address, pincode
      FROM clients
      WHERE (latitude IS NULL OR longitude IS NULL)
        AND (address IS NOT NULL OR pincode IS NOT NULL)
      ORDER BY 
        CASE 
          WHEN pincode IS NOT NULL THEN 1  -- Prioritize clients with pincode
          ELSE 2 
        END,
        id DESC
      LIMIT 1000
    `);

    const clientsToGeocode = result.rows;
    
    if (clientsToGeocode.length === 0) {
      console.log("✅ No clients need geocoding");
      return;
    }

    console.log(`📍 Found ${clientsToGeocode.length} clients needing geocoding`);

    // Process in smaller batches with rate limiting
    const BATCH_SIZE = 3;
    const DELAY_BETWEEN_BATCHES = 1500; // 1.5 seconds
    
    for (let i = 0; i < clientsToGeocode.length; i += BATCH_SIZE) {
      const batch = clientsToGeocode.slice(i, i + BATCH_SIZE);
      
      // Process batch sequentially to avoid rate limits
      for (const client of batch) {
        const result = await geocodeSingleClientWithStrategies(client);
        
        processed++;
        
        if (result.success) {
          updated++;
          console.log(`   ✅ [${processed}/${clientsToGeocode.length}] ${client.name} → ${result.strategy}`);
        } else {
          failed++;
          failures.push({
            id: client.id,
            name: client.name,
            address: client.address,
            pincode: client.pincode,
            error: result.error
          });
          console.log(`   ❌ [${processed}/${clientsToGeocode.length}] ${client.name} → ${result.error}`);
        }
        
        // Small delay between individual requests
        await sleep(300);
      }
      
      // Log progress every batch
      const progress = ((processed / clientsToGeocode.length) * 100).toFixed(1);
      console.log(`\n📊 Progress: ${progress}% | Updated: ${updated} | Failed: ${failed}\n`);
      
      // Longer delay between batches
      if (i + BATCH_SIZE < clientsToGeocode.length) {
        await sleep(DELAY_BETWEEN_BATCHES);
      }
    }

    const duration = ((Date.now() - startTime) / 1000).toFixed(2);
    console.log(`\n✅ Geocoding completed in ${duration}s`);
    console.log(`   📊 Total: ${processed}`);
    console.log(`   ✅ Success: ${updated} (${((updated/processed)*100).toFixed(1)}%)`);
    console.log(`   ❌ Failed: ${failed} (${((failed/processed)*100).toFixed(1)}%)`);

    // Log failed addresses for manual review
    if (failures.length > 0) {
      console.log(`\n⚠️ Failed addresses (sample):`);
      failures.slice(0, 10).forEach(f => {
        console.log(`   - ${f.name}: ${f.address?.substring(0, 50)}... (PIN: ${f.pincode || 'N/A'})`);
      });
      
      // Save failures to database for later retry
      await saveFailedGeocodingAttempts(failures);
    }

  } catch (error) {
    console.error("❌ Background geocoding error:", error);
  }
}

/**
 * Try multiple geocoding strategies in order of reliability
 */
async function geocodeSingleClientWithStrategies(client) {
  const GOOGLE_MAPS_API_KEY = process.env.GOOGLE_MAPS_API_KEY;
  
  if (!GOOGLE_MAPS_API_KEY) {
    return { success: false, error: "No API key configured" };
  }

  // Extract pincode from address if not present
  const pincode = client.pincode || extractPincodeFromAddress(client.address);

  // =============================================
  // STRATEGY 1: PINCODE ONLY (Highest Success Rate)
  // =============================================
  if (pincode) {
    const result = await tryGeocode(pincode, GOOGLE_MAPS_API_KEY);
    if (result.success) {
      await updateClientLocation(client.id, result.latitude, result.longitude, pincode);
      return { success: true, strategy: "Pincode Only", ...result };
    }
  }

  // =============================================
  // STRATEGY 2: CITY + PINCODE
  // =============================================
  if (client.address && pincode) {
    const city = extractCityFromAddress(client.address);
    if (city) {
      const cityPinQuery = `${city}, ${pincode}, India`;
      const result = await tryGeocode(cityPinQuery, GOOGLE_MAPS_API_KEY);
      if (result.success) {
        await updateClientLocation(client.id, result.latitude, result.longitude, pincode);
        return { success: true, strategy: "City + Pincode", ...result };
      }
    }
  }

  // =============================================
  // STRATEGY 3: SIMPLIFIED ADDRESS
  // =============================================
  if (client.address) {
    const simplified = simplifyAddress(client.address);
    if (simplified) {
      const result = await tryGeocode(simplified, GOOGLE_MAPS_API_KEY);
      if (result.success) {
        const finalPincode = result.pincode || pincode;
        await updateClientLocation(client.id, result.latitude, result.longitude, finalPincode);
        return { success: true, strategy: "Simplified Address", ...result };
      }
    }
  }

  // =============================================
  // STRATEGY 4: AREA + PINCODE
  // =============================================
  if (client.address && pincode) {
    const area = extractAreaFromAddress(client.address);
    if (area) {
      const areaPinQuery = `${area}, ${pincode}`;
      const result = await tryGeocode(areaPinQuery, GOOGLE_MAPS_API_KEY);
      if (result.success) {
        await updateClientLocation(client.id, result.latitude, result.longitude, pincode);
        return { success: true, strategy: "Area + Pincode", ...result };
      }
    }
  }

  // =============================================
  // STRATEGY 5: FULL ADDRESS (Last Resort)
  // =============================================
  if (client.address) {
    const fullAddress = `${client.address}${pincode ? ', ' + pincode : ''}, India`;
    const result = await tryGeocode(fullAddress, GOOGLE_MAPS_API_KEY);
    if (result.success) {
      const finalPincode = result.pincode || pincode;
      await updateClientLocation(client.id, result.latitude, result.longitude, finalPincode);
      return { success: true, strategy: "Full Address", ...result };
    }
  }

  // =============================================
  // ALL STRATEGIES FAILED
  // =============================================
  return { 
    success: false, 
    error: "All geocoding strategies failed",
    clientId: client.id
  };
}

/**
 * Try geocoding a single address
 */
async function tryGeocode(address, apiKey) {
  try {
    const url = `https://maps.googleapis.com/maps/api/geocode/json?address=${encodeURIComponent(address)}&region=in&key=${apiKey}`;
    
    const response = await fetch(url);
    const data = await response.json();
    
    // Handle rate limiting
    if (data.status === 'OVER_QUERY_LIMIT') {
      console.log(`   ⏳ Rate limit hit, waiting...`);
      await sleep(3000);
      return { success: false, error: 'OVER_QUERY_LIMIT' };
    }
    
    // Handle no results
    if (data.status !== 'OK' || !data.results || data.results.length === 0) {
      return { success: false, error: data.status || 'NO_RESULTS' };
    }

    const result = data.results[0];
    const location = result.geometry.location;
    
    // Validate coordinates are in India (roughly)
    const latitude = location.lat;
    const longitude = location.lng;
    
    if (latitude < 6 || latitude > 37 || longitude < 68 || longitude > 98) {
      return { success: false, error: 'COORDINATES_OUT_OF_INDIA' };
    }
    
    // Extract pincode from result
    const components = result.address_components;
    const pincodeComponent = components.find(c => 
      c.types.includes('postal_code')
    );
    const pincode = pincodeComponent?.long_name || null;

    return { 
      success: true,
      latitude,
      longitude,
      pincode,
      formattedAddress: result.formatted_address
    };

  } catch (error) {
    return { success: false, error: error.message };
  }
}

/**
 * Update client with geocoded location
 */
async function updateClientLocation(clientId, latitude, longitude, pincode) {
  await pool.query(
    `UPDATE clients 
     SET latitude = $1, 
         longitude = $2, 
         pincode = COALESCE(pincode, $3),
         updated_at = NOW()
     WHERE id = $4`,
    [latitude, longitude, pincode, clientId]
  );
}

/**
 * Extract pincode from address text
 */
function extractPincodeFromAddress(address) {
  if (!address) return null;
  
  // Match 6-digit Indian pincode
  const match = address.match(/\b[1-9][0-9]{5}\b/);
  return match ? match[0] : null;
}

/**
 * Extract city name from address
 */
function extractCityFromAddress(address) {
  if (!address) return null;
  
  const majorCities = [
    'Mumbai', 'Delhi', 'Bangalore', 'Bengaluru', 'Hyderabad', 'Ahmedabad', 
    'Chennai', 'Kolkata', 'Pune', 'Jaipur', 'Surat', 'Lucknow', 'Kanpur',
    'Nagpur', 'Indore', 'Thane', 'Bhopal', 'Visakhapatnam', 'Pimpri', 'Patna',
    'Vadodara', 'Ghaziabad', 'Ludhiana', 'Agra', 'Nashik', 'Faridabad',
    'Meerut', 'Rajkot', 'Varanasi', 'Srinagar', 'Aurangabad', 'Dhanbad',
    'Amritsar', 'Navi Mumbai', 'Allahabad', 'Ranchi', 'Howrah', 'Coimbatore',
    'Jabalpur', 'Gwalior', 'Vijayawada', 'Jodhpur', 'Madurai', 'Raipur',
    'Kota', 'Guwahati', 'Chandigarh', 'Solapur', 'Hubli', 'Bareilly',
    'Moradabad', 'Mysore', 'Gurgaon', 'Aligarh', 'Jalandhar', 'Noida'
  ];
  
  for (const city of majorCities) {
    const regex = new RegExp(`\\b${city}\\b`, 'i');
    if (regex.test(address)) {
      return city;
    }
  }
  
  return null;
}

/**
 * Extract area/locality from address
 */
function extractAreaFromAddress(address) {
  if (!address) return null;
  
  // Common patterns: "Near X", "Opposite X", "X Road", "X Nagar"
  const areaPatterns = [
    /(?:near|opp|opposite)\s+([A-Za-z\s]+?)(?:,|\.|\s+\d)/i,
    /([A-Za-z\s]+?)\s+(?:road|rd|nagar|colony|area|sector)/i,
  ];
  
  for (const pattern of areaPatterns) {
    const match = address.match(pattern);
    if (match && match[1]) {
      return match[1].trim();
    }
  }
  
  return null;
}

/**
 * Simplify address by removing noise
 */
function simplifyAddress(address) {
  if (!address) return null;
  
  let simplified = address;
  
  // Remove shop/flat numbers
  simplified = simplified.replace(/\b(shop|flat|unit|office|room|plot|floor)\s*(no\.?|number|#)?\s*[a-z0-9\-\/]+,?\s*/gi, '');
  
  // Remove phone numbers
  simplified = simplified.replace(/\b\d{10}\b/g, '');
  simplified = simplified.replace(/\+?\d{1,4}[\s-]?\d{3,4}[\s-]?\d{3,4}/g, '');
  
  // Remove email addresses
  simplified = simplified.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '');
  
  // Remove multiple commas/spaces
  simplified = simplified.replace(/,+/g, ',').replace(/\s+/g, ' ').trim();
  
  // Remove leading/trailing commas
  simplified = simplified.replace(/^,+|,+$/g, '').trim();
  
  return simplified.length > 10 ? simplified : null;
}

/**
 * Save failed geocoding attempts for manual review
 */
async function saveFailedGeocodingAttempts(failures) {
  try {
    for (const failure of failures) {
      await pool.query(
        `INSERT INTO geocoding_failures (client_id, address, pincode, error, attempted_at)
         VALUES ($1, $2, $3, $4, NOW())
         ON CONFLICT (client_id) DO UPDATE 
         SET attempted_at = NOW(), error = $4, attempt_count = geocoding_failures.attempt_count + 1`,
        [failure.id, failure.address, failure.pincode, failure.error]
      );
    }
    console.log(`\n💾 Saved ${failures.length} failed attempts to database`);
  } catch (error) {
    console.error("Failed to save geocoding failures:", error);
  }
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ============================================
// MANUAL RETRY FUNCTION (Run separately)
// ============================================
export async function retryFailedGeocodings() {
  console.log("🔄 Retrying failed geocoding attempts...");
  
  const result = await pool.query(`
    SELECT c.id, c.name, c.address, c.pincode
    FROM clients c
    INNER JOIN geocoding_failures gf ON c.id = gf.client_id
    WHERE c.latitude IS NULL 
      AND gf.attempt_count < 3
      AND gf.attempted_at < NOW() - INTERVAL '1 day'
    LIMIT 100
  `);
  
  console.log(`Found ${result.rows.length} clients to retry`);
  
  for (const client of result.rows) {
    const geocodeResult = await geocodeSingleClientWithStrategies(client);
    
    if (geocodeResult.success) {
      console.log(`✅ Retry success: ${client.name}`);
      // Remove from failures table
      await pool.query(`DELETE FROM geocoding_failures WHERE client_id = $1`, [client.id]);
    } else {
      console.log(`❌ Retry failed: ${client.name}`);
    }
    
    await sleep(500);
  }
}
