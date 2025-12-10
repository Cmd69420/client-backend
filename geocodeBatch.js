import { pool } from "../db.js";
import { getPincodeFromLatLon } from "./geocode.js";

/**
 * Background job to geocode clients missing location data
 * Safe for large datasets with batching and concurrency control
 */
export async function startBackgroundGeocode() {
  console.log("🌍 Starting background geocoding job...");
  
  // Don't await - let it run in background
  geocodeClientsInBackground().catch(err => {
    console.error("❌ Background geocoding job failed:", err);
  });
}

async function geocodeClientsInBackground() {
  const startTime = Date.now();
  let processed = 0;
  let updated = 0;
  let failed = 0;

  try {
    // Find clients missing lat/lon but have address
    const result = await pool.query(`
      SELECT id, address, pincode
      FROM clients
      WHERE address IS NOT NULL
        AND address != ''
        AND (latitude IS NULL OR longitude IS NULL)
      LIMIT 1000
    `);

    const clientsToGeocode = result.rows;
    
    if (clientsToGeocode.length === 0) {
      console.log("✅ No clients need geocoding");
      return;
    }

    console.log(`📍 Found ${clientsToGeocode.length} clients needing geocoding`);

    // Process in batches with concurrency control
    const BATCH_SIZE = 5; // Reduced from 10
    const CONCURRENCY = 2; // Reduced from 3 - more conservative
    
    for (let i = 0; i < clientsToGeocode.length; i += BATCH_SIZE) {
      const batch = clientsToGeocode.slice(i, i + BATCH_SIZE);
      
      // Process batch with limited concurrency
      const batchPromises = [];
      for (let j = 0; j < batch.length; j += CONCURRENCY) {
        const chunk = batch.slice(j, j + CONCURRENCY);
        const chunkPromise = Promise.all(
          chunk.map(client => geocodeSingleClient(client))
        );
        batchPromises.push(chunkPromise);
      }
      
      const batchResults = await Promise.all(batchPromises);
      const flatResults = batchResults.flat();
      
      // Count results
      flatResults.forEach(result => {
        processed++;
        if (result.success) updated++;
        else {
          failed++;
          // Log failures for debugging
          if (result.error && result.error !== 'ZERO_RESULTS') {
            console.log(`   ⚠️ Client ${result.clientId} failed: ${result.error}`);
          }
        }
      });
      
      // Log progress every batch
      console.log(`   📊 Progress: ${processed}/${clientsToGeocode.length} (${updated} updated, ${failed} failed)`);
      
      // Longer delay between batches to avoid rate limits
      if (i + BATCH_SIZE < clientsToGeocode.length) {
        await sleep(1000); // Increased from 500ms to 1000ms
      }
    }

    const duration = ((Date.now() - startTime) / 1000).toFixed(2);
    console.log(`✅ Background geocoding completed in ${duration}s`);
    console.log(`   📊 Total: ${processed}, Updated: ${updated}, Failed: ${failed}`);

  } catch (error) {
    console.error("❌ Background geocoding error:", error);
  }
}

async function geocodeSingleClient(client) {
  try {
    const GOOGLE_MAPS_API_KEY = process.env.GOOGLE_MAPS_API_KEY;
    
    if (!GOOGLE_MAPS_API_KEY) {
      return { success: false, clientId: client.id, error: "No API key" };
    }

    // Try multiple address variations in order of specificity
    const addressVariations = generateAddressVariations(client.address, client.pincode);
    
    let geocodeResult = null;
    let usedAddress = null;
    let attemptCount = 0;

    // Try each variation until one works (max 3 attempts to avoid too many API calls)
    for (const addressVar of addressVariations.slice(0, 3)) {
      attemptCount++;
      const result = await tryGeocode(addressVar, GOOGLE_MAPS_API_KEY);
      
      if (result.success) {
        geocodeResult = result;
        usedAddress = addressVar;
        break;
      }
      
      // If rate limited, stop trying
      if (result.error === 'OVER_QUERY_LIMIT') {
        console.log(`   ⚠️ Rate limit hit, backing off...`);
        await sleep(2000);
        return { 
          success: false, 
          clientId: client.id, 
          error: 'OVER_QUERY_LIMIT'
        };
      }
      
      // Small delay between attempts (only if more attempts remain)
      if (attemptCount < 3 && attemptCount < addressVariations.length) {
        await sleep(300); // Increased from 200ms
      }
    }

    if (!geocodeResult) {
      return { 
        success: false, 
        clientId: client.id, 
        error: "All address variations failed" 
      };
    }

    const { latitude, longitude, pincode } = geocodeResult;

    // Update database
    await pool.query(
      `UPDATE clients 
       SET latitude = $1, 
           longitude = $2, 
           pincode = COALESCE(pincode, $3),
           updated_at = NOW()
       WHERE id = $4`,
      [latitude, longitude, pincode, client.id]
    );

    return { 
      success: true, 
      clientId: client.id,
      latitude,
      longitude,
      pincode,
      usedAddress 
    };

  } catch (error) {
    return { 
      success: false, 
      clientId: client.id, 
      error: error.message 
    };
  }
}

/**
 * Generate progressively simpler address variations
 * Strategy: Pincode first (most reliable) → City + Pincode → Simplified address
 */
function generateAddressVariations(address, pincode) {
  const variations = [];
  
  if (!address) return variations;

  // STRATEGY CHANGE: Start with most reliable options first!
  
  // 1. **PINCODE ONLY** (Most reliable - always works if valid)
  if (pincode) {
    variations.push(pincode);
  }

  // 2. Extract city name + pincode
  const cityMatch = address.match(/\b(Mumbai|Delhi|Bangalore|Bengaluru|Chennai|Kolkata|Hyderabad|Pune|Ahmedabad|Jaipur|Lucknow|Kanpur|Nagpur|Indore|Thane|Bhopal|Visakhapatnam|Pimpri|Patna|Vadodara|Ghaziabad|Ludhiana|Agra|Nashik|Faridabad|Meerut|Rajkot|Kalyan|Vasai|Varanasi|Srinagar|Aurangabad|Dhanbad|Amritsar|Navi Mumbai|Allahabad|Ranchi|Howrah|Coimbatore|Jabalpur|Gwalior|Vijayawada|Jodhpur|Madurai|Raipur|Kota|Guwahati|Chandigarh|Solapur|Hubli|Dharwad|Bareilly|Moradabad|Mysore|Gurgaon|Aligarh|Jalandhar|Tiruchirappalli|Bhubaneswar|Salem|Mira Bhayandar|Warangal|Thiruvananthapuram|Guntur|Bhiwandi|Saharanpur|Gorakhpur|Bikaner|Amravati|Noida|Jamshedpur|Bhilai|Cuttack|Firozabad|Kochi|Nellore|Bhavnagar|Dehradun|Durgapur|Asansol|Rourkela|Nanded|Kolhapur|Ajmer|Akola|Gulbarga|Jamnagar|Ujjain|Loni|Siliguri|Jhansi|Ulhasnagar|Jammu|Sangli|Mangalore|Erode|Belgaum|Ambattur|Tirunelveli|Malegaon|Gaya|Jalgaon|Udaipur|Maheshtala)\b/i);
  
  if (cityMatch && pincode) {
    const cityName = cityMatch[0];
    variations.push(`${cityName}, ${pincode}`);
  }

  // 3. Remove shop/flat/unit numbers for cleaner address
  const withoutShop = address.replace(/\b(shop|flat|unit|office|room|plot)\s*(no\.?|number)?\s*[a-z0-9\-\/]+,?\s*/gi, '');
  if (withoutShop !== address && withoutShop.length > 10) {
    variations.push(withoutShop);
  }

  // Remove duplicates and empty strings
  return [...new Set(variations)].filter(v => v && v.length > 0);
}

/**
 * Try geocoding a single address variation
 */
async function tryGeocode(address, apiKey) {
  try {
    const url = `https://maps.googleapis.com/maps/api/geocode/json?address=${encodeURIComponent(address)}&key=${apiKey}`;
    
    const response = await fetch(url);
    const data = await response.json();
    
    if (data.status !== 'OK' || !data.results || data.results.length === 0) {
      return { success: false, error: data.status };
    }

    const location = data.results[0].geometry.location;
    const latitude = location.lat;
    const longitude = location.lng;
    
    // Get pincode from address components
    const components = data.results[0].address_components;
    const pincodeComponent = components.find(c => 
      c.types.includes('postal_code')
    );
    const pincode = pincodeComponent?.long_name || null;

    return { 
      success: true,
      latitude,
      longitude,
      pincode 
    };

  } catch (error) {
    return { success: false, error: error.message };
  }
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
