function setStatus(msg) {
  document.getElementById("status").textContent = msg;
}

function pemToArrayBuffer(pem) {
  const b64 = pem
    .replace("-----BEGIN PUBLIC KEY-----", "")
    .replace("-----END PUBLIC KEY-----", "")
    .replace(/\s/g, "");
  const binary = atob(b64);
  const buffer = new ArrayBuffer(binary.length);
  const view = new Uint8Array(buffer);
  for (let i = 0; i < binary.length; i++) view[i] = binary.charCodeAt(i);
  return buffer;
}

function bufToB64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

async function sha256Hex(bytes) {
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function submitVote() {
  try {
    setStatus("Working...");

    const electionId = Number(document.getElementById("electionId").value);
    const nationalId = document.getElementById("nationalId").value.trim();
    const candidate = document.getElementById("candidate").value;

    if (!electionId || electionId < 1) throw new Error("Invalid election id");
    if (!nationalId) throw new Error("National ID is required (test)");

    // 1) Fetch election public key
    const pkResp = await fetch(`/elections/${electionId}/public-key`);
    if (!pkResp.ok) throw new Error("Failed to fetch election public key");
    const pkData = await pkResp.json();

    const publicKey = await crypto.subtle.importKey(
      "spki",
      pemToArrayBuffer(pkData.public_key_pem),
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["encrypt"]
    );

    // 2) Create credential token (random 32 bytes) and request signature (MVP)
    const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
    const tokenB64 = bufToB64(tokenBytes.buffer);

    const credResp = await fetch("/credential/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ national_id: nationalId, token_b64: tokenB64 })
    });
    const credData = await credResp.json();
    if (!credResp.ok) throw new Error(credData?.description || "Credential issue failed");

    const signatureHex = credData.signature_hex;

    // 3) Hybrid encrypt ballot: AES-GCM for vote, RSA-OAEP encrypt AES key
    const encoder = new TextEncoder();
    const voteBytes = encoder.encode(JSON.stringify({ candidate }));

    const aesKey = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt"]
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      aesKey,
      voteBytes
    );

    const rawAes = await crypto.subtle.exportKey("raw", aesKey);
    const encKey = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, rawAes);

    // bundle as bytes for hashing + storage
    const bundle = new Uint8Array([
      ...new Uint8Array(encKey),
      ...iv,
      ...new Uint8Array(ciphertext)
    ]);

    const ballotHashHex = await sha256Hex(bundle);

    // store ciphertext as base64 of bundle (simple MVP storage)
    const ciphertextB64 = bufToB64(bundle.buffer);

    // 4) Submit vote
    const voteResp = await fetch(`/elections/${electionId}/vote`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        token_b64: tokenB64,
        signature_hex: signatureHex,
        ciphertext_b64: ciphertextB64,
        ballot_hash_hex: ballotHashHex
      })
    });

    const voteData = await voteResp.json();
    if (!voteResp.ok) {
      throw new Error(voteData?.description || JSON.stringify(voteData));
    }

    setStatus(`✅ ${voteData.message}\nballot_hash: ${ballotHashHex}`);
  } catch (e) {
    setStatus(`❌ Error: ${e.message}`);
  }
}