// node_client_demo.js — Démo interopérabilité Node.js <-> cagoule-api
// Usage: node node_client_demo.js

const BASE_URL = process.env.CAGOULE_API_URL || "http://localhost:8000";
const API_KEY  = process.env.CAGOULE_API_KEY  || "";

const headers = {
  "Content-Type": "application/json",
  "Authorization": `Bearer ${API_KEY}`,
};

async function request(path, body) {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  return res.json();
}

async function main() {
  console.log(`\n[Node.js] Connexion à ${BASE_URL}`);

  // Health check
  const health = await fetch(`${BASE_URL}/v1/health`).then(r => r.json());
  console.log("[health]", health);

  // Roundtrip texte
  const plaintext = "Secret depuis Node.js 🚀";
  const password  = "node_demo_password";

  console.log(`\n[encrypt] plaintext = "${plaintext}"`);
  const encRes = await request("/v1/encrypt", { plaintext, password });
  console.log("[encrypt] ciphertext_b64 =", encRes.ciphertext_b64?.slice(0, 40) + "...");

  console.log("\n[decrypt] ...");
  const decRes = await request("/v1/decrypt", {
    ciphertext_b64: encRes.ciphertext_b64,
    password,
  });
  console.log("[decrypt] plaintext =", decRes.plaintext);

  if (decRes.plaintext === plaintext) {
    console.log("\n✅ Roundtrip Node.js <-> cagoule-api : OK");
  } else {
    console.error("\n❌ ECHEC : plaintext ne correspond pas");
    process.exit(1);
  }
}

main().catch(err => { console.error(err); process.exit(1); });
