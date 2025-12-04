import axios from "axios";

export async function getPincodeFromLatLon(lat, lon) {
  try {
    const apiKey = process.env.GOOGLE_MAPS_API_KEY;
    const url = `https://maps.googleapis.com/maps/api/geocode/json?latlng=${lat},${lon}&key=${apiKey}`;

    const res = await axios.get(url);
    const result = res.data.results?.[0]?.address_components || [];

    const pincode = result.find(c => c.types.includes("postal_code"))?.long_name;
    return pincode || null;

  } catch (err) {
    console.error("GEOCODE_PINCODE_ERROR:", err.message);
    return null;
  }
}
