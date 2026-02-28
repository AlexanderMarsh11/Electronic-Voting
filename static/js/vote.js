async function submitVote() {

    const candidate = document.getElementById("candidate").value;
    const encoder = new TextEncoder();
    const voteData = encoder.encode(candidate);

    // generaton AES
    const aesKey = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt"]
    );

    const iv = crypto.getRandomValues(new Uint8Array(12));

    //  voting encryption AES
    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        aesKey,
        voteData
    );

    //  export keys AES
    const rawKey = await crypto.subtle.exportKey("raw", aesKey);

    // bring public key election from the browser
    const response = await fetch("/elections/1/public-key");
    const data = await response.json();

    const pem = data.public_key_pem;
    const binaryDer = pemToArrayBuffer(pem);

    const publicKey = await crypto.subtle.importKey(
        "spki",
        binaryDer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"]
    );

    // RSA Key encryptingusing AES
    const encryptedKey = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        rawKey
    );

    console.log("Encrypted AES key:", new Uint8Array(encryptedKey));
    console.log("Encrypted vote:", new Uint8Array(ciphertext));

    alert("Vote encrypted successfully (see console)");
}

function pemToArrayBuffer(pem) {
    const b64 = pem
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replace(/\s/g, "");

    const binary = atob(b64);
    const buffer = new ArrayBuffer(binary.length);
    const view = new Uint8Array(buffer);

    for (let i = 0; i < binary.length; i++) {
        view[i] = binary.charCodeAt(i);
    }

    return buffer;
}