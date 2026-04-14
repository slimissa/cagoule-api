// node_client_demo.js — Démo interopérabilité Node.js <-> cagoule-api
// Usage: node node_client_demo.js

const BASE_URL = process.env.CAGOULE_API_URL || "http://localhost:8000";
const API_KEY = process.env.CAGOULE_API_KEY;

// Vérification de l'API key
if (!API_KEY) {
  console.error("❌ Erreur: CAGOULE_API_KEY non définie");
  console.error("   export CAGOULE_API_KEY=your-key-here");
  console.error("   Ou lancez avec: CAGOULE_API_KEY=test-key-123 node node_client_demo.js");
  process.exit(1);
}

const headers = {
  "Content-Type": "application/json",
  "Authorization": `Bearer ${API_KEY}`,
  // Alternative: "X-API-Key": API_KEY (supporté aussi par l'API)
};

/**
 * Fait une requête POST à l'API
 * @param {string} path - Chemin de l'endpoint (ex: /v1/encrypt)
 * @param {object} body - Corps de la requête
 * @returns {Promise<object>} - Réponse JSON
 */
async function request(path, body) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000); // 30s timeout
  
  try {
    const res = await fetch(`${BASE_URL}${path}`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    clearTimeout(timeout);
    
    // Vérifier le statut HTTP
    if (!res.ok) {
      let errorMessage;
      try {
        const error = await res.json();
        errorMessage = error.error?.message || error.message || res.statusText;
      } catch {
        errorMessage = res.statusText;
      }
      throw new Error(`HTTP ${res.status}: ${errorMessage}`);
    }
    
    return res.json();
  } catch (err) {
    clearTimeout(timeout);
    if (err.name === 'AbortError') {
      throw new Error(`Timeout après 30s sur ${path}`);
    }
    throw err;
  }
}

/**
 * Health check (GET, sans auth)
 */
async function healthCheck() {
  const res = await fetch(`${BASE_URL}/v1/health`);
  if (!res.ok) {
    throw new Error(`Health check échoué: HTTP ${res.status}`);
  }
  return res.json();
}

/**
 * Démonstration principale
 */
async function main() {
  console.log(`\n🚀 Démo Node.js - cagoule-api`);
  console.log(`📡 API URL: ${BASE_URL}`);
  console.log(`🔑 API Key: ${API_KEY.substring(0, 8)}...${API_KEY.substring(API_KEY.length - 4)}\n`);

  // 1. Health check
  console.log("🏥 Health check...");
  const health = await healthCheck();
  console.log(`   ✅ ${health.status} (v${health.version})`);
  console.log(`   🔐 CAGOULE disponible: ${health.cagoule_available ? '✅' : '❌'}\n`);

  if (!health.cagoule_available) {
    console.warn("⚠️  Attention: CAGOULE non disponible sur le serveur");
  }

  // 2. Roundtrip texte
  const plaintext = "Secret depuis Node.js 🚀";
  const password = "node_demo_password";

  console.log("📝 Test chiffrement/déchiffrement...");
  console.log(`   Texte original: "${plaintext}"`);

  // Chiffrement
  console.log("   🔐 Chiffrement...");
  const encRes = await request("/v1/encrypt", { plaintext, password });
  
  if (!encRes.ciphertext_b64) {
    throw new Error("Réponse de chiffrement invalide: ciphertext_b64 manquant");
  }
  
  const cipherPreview = encRes.ciphertext_b64.length > 40 
    ? `${encRes.ciphertext_b64.substring(0, 40)}...` 
    : encRes.ciphertext_b64;
  console.log(`   📦 Ciphertext (${encRes.ciphertext_b64.length} chars): ${cipherPreview}`);

  // Déchiffrement
  console.log("   🔓 Déchiffrement...");
  const decRes = await request("/v1/decrypt", {
    ciphertext_b64: encRes.ciphertext_b64,
    password,
  });
  
  if (!decRes.plaintext) {
    throw new Error("Réponse de déchiffrement invalide: plaintext manquant");
  }
  
  console.log(`   📄 Déchiffré: "${decRes.plaintext}"`);

  // Vérification
  if (decRes.plaintext === plaintext) {
    console.log("\n✅ SUCCÈS! Round-trip Node.js <-> cagoule-api complet.");
  } else {
    console.error("\n❌ ÉCHEC: Le texte déchiffré ne correspond pas à l'original.");
    console.error(`   Attendu: "${plaintext}"`);
    console.error(`   Reçu:   "${decRes.plaintext}"`);
    process.exit(1);
  }

  // 3. Test optionnel: chiffrement avec erreur
  console.log("\n🧪 Test avec mauvais mot de passe...");
  try {
    await request("/v1/decrypt", {
      ciphertext_b64: encRes.ciphertext_b64,
      password: "wrong-password",
    });
    console.error("   ❌ Devrait échouer mais a réussi!");
  } catch (err) {
    if (err.message.includes("422") || err.message.includes("DECRYPTION_FAILED")) {
      console.log("   ✅ Correctement rejeté (mauvais mot de passe)");
    } else {
      console.log(`   ⚠️  Erreur inattendue: ${err.message}`);
    }
  }

  console.log("\n✨ Démo terminée avec succès!");
}

// Exécution avec gestion d'erreurs
main().catch(err => {
  console.error("\n💥 Erreur fatale:", err.message);
  if (err.cause) {
    console.error("   Cause:", err.cause);
  }
  process.exit(1);
});