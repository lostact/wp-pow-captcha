/**
 * WP PoW Captcha — Web Worker
 *
 * Runs proof-of-work hashing in a dedicated worker thread.
 * Receives { challenge, difficulty } and posts back the numeric solution.
 *
 * Uses a synchronous SHA-256 implementation to avoid per-iteration async
 * overhead from crypto.subtle.digest Promises, which makes higher
 * difficulty levels feasible. Constants are from NIST FIPS 180-4.
 */

self.onmessage = function (e) {
    var challenge  = e.data.challenge;
    var difficulty = e.data.difficulty;
    var prefix     = '0'.repeat(difficulty);
    var counter    = 0;
    var yieldEvery = 10000; // Yield to event loop every N iterations.

    function tick() {
        var limit = counter + yieldEvery;
        while (counter < limit) {
            var hex = sha256(challenge + counter);
            if (hex.startsWith(prefix)) {
                self.postMessage(counter.toString());
                return;
            }
            counter++;
        }
        // Yield to the event loop to keep the worker responsive.
        setTimeout(tick, 0);
    }

    tick();
};

/**
 * Synchronous SHA-256 implementation.
 *
 * Round constants (K) and initial hash values (H) are standardised
 * by NIST FIPS 180-4 and are identical in every SHA-256 implementation.
 *
 * @param {string} message The input string.
 * @return {string} Lowercase hex-encoded SHA-256 digest.
 */
function sha256(message) {
    // Round constants: floor(2^32 × frac(cuberoot(prime_i))) for i = 0..63.
    var K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    // Initial hash values: floor(2^32 × frac(sqrt(prime_i))) for i = 0..7.
    var H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];

    // Pre-processing: convert string to byte array (UTF-8).
    var bytes = [];
    for (var i = 0; i < message.length; i++) {
        var c = message.charCodeAt(i);
        if (c < 128) {
            bytes.push(c);
        } else if (c < 2048) {
            bytes.push((c >> 6) | 192);
            bytes.push((c & 63) | 128);
        } else {
            bytes.push((c >> 12) | 224);
            bytes.push(((c >> 6) & 63) | 128);
            bytes.push((c & 63) | 128);
        }
    }

    var bitLen = bytes.length * 8;

    // Append bit '1' (byte 0x80).
    bytes.push(0x80);

    // Pad with zeros until length ≡ 448 mod 512 (56 bytes mod 64).
    while (bytes.length % 64 !== 56) {
        bytes.push(0);
    }

    // Append original length as 64-bit big-endian.
    var high = Math.floor(bitLen / 0x100000000);
    var low  = bitLen >>> 0;
    for (var i = 56; i >= 0; i -= 8) {
        if (i >= 32) {
            bytes.push((high >>> i) & 0xff);
        } else {
            bytes.push((low >>> i) & 0xff);
        }
    }

    // Process each 512-bit (64-byte) block.
    for (var offset = 0; offset < bytes.length; offset += 64) {
        var W = new Array(64);

        // Copy chunk into first 16 words.
        for (var i = 0; i < 16; i++) {
            W[i] = (bytes[offset + i * 4] << 24) |
                    (bytes[offset + i * 4 + 1] << 16) |
                    (bytes[offset + i * 4 + 2] << 8) |
                    (bytes[offset + i * 4 + 3]);
        }

        // Extend the first 16 words into the remaining 48 words.
        for (var i = 16; i < 64; i++) {
            var s0 = ((W[i - 15] >>> 7)  | (W[i - 15] << 25)) ^
                     ((W[i - 15] >>> 18) | (W[i - 15] << 14)) ^
                     (W[i - 15] >>> 3);
            var s1 = ((W[i - 2] >>> 17) | (W[i - 2] << 15)) ^
                     ((W[i - 2] >>> 19) | (W[i - 2] << 13)) ^
                     (W[i - 2] >>> 10);
            W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
        }

        var a = H[0], b = H[1], c = H[2], d = H[3];
        var e = H[4], f = H[5], g = H[6], h = H[7];

        for (var i = 0; i < 64; i++) {
            var S1 = ((e >>> 6) | (e << 26)) ^
                     ((e >>> 11) | (e << 21)) ^
                     ((e >>> 25) | (e << 7));
            var ch = (e & f) ^ (~e & g);
            var temp1 = (h + S1 + ch + K[i] + W[i]) | 0;
            var S0 = ((a >>> 2) | (a << 30)) ^
                     ((a >>> 13) | (a << 19)) ^
                     ((a >>> 22) | (a << 10));
            var maj = (a & b) ^ (a & c) ^ (b & c);
            var temp2 = (S0 + maj) | 0;

            h = g; g = f; f = e; e = (d + temp1) | 0;
            d = c; c = b; b = a; a = (temp1 + temp2) | 0;
        }

        H[0] = (H[0] + a) | 0;
        H[1] = (H[1] + b) | 0;
        H[2] = (H[2] + c) | 0;
        H[3] = (H[3] + d) | 0;
        H[4] = (H[4] + e) | 0;
        H[5] = (H[5] + f) | 0;
        H[6] = (H[6] + g) | 0;
        H[7] = (H[7] + h) | 0;
    }

    // Produce hex string.
    var hex = '';
    for (var i = 0; i < 8; i++) {
        var h = H[i];
        hex += ((h >>> 28) & 0xf).toString(16) +
               ((h >>> 24) & 0xf).toString(16) +
               ((h >>> 20) & 0xf).toString(16) +
               ((h >>> 16) & 0xf).toString(16) +
               ((h >>> 12) & 0xf).toString(16) +
               ((h >>> 8)  & 0xf).toString(16) +
               ((h >>> 4)  & 0xf).toString(16) +
               (h & 0xf).toString(16);
    }
    return hex;
}
