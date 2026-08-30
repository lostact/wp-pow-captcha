/**
 * Proof of Work Captcha — Web Worker
 *
 * Runs proof-of-work hashing in a dedicated worker thread.
 * Receives { challenge, difficulty } and posts back the numeric solution.
 *
 * Uses a synchronous SHA-256 implementation to avoid per-iteration async
 * overhead from crypto.subtle.digest Promises, which makes higher
 * difficulty levels feasible. Constants are from NIST FIPS 180-4.
 */

var FRACTION_THRESHOLDS = [256, 239, 223, 208, 194, 181, 169, 158, 147, 137];

self.onmessage = function (e) {
    var data = e.data || {};

    if (data.action === 'benchmark') {
        runBenchmark(data.duration || 1500);
        return;
    }

    runSolve(data.challenge, Number(data.difficulty), data.startCounter || 0, Number(data.version));
};

/** Solve a challenge and periodically report real progress. */
function runSolve(challenge, difficulty, startCounter, version) {
    if (typeof challenge !== 'string' || version !== 3 || difficulty < 0 || difficulty > 140) {
        self.postMessage({ type: 'error', message: 'Invalid proof-of-work parameters.' });
        return;
    }

    var counter = Number(startCounter) || 0;
    var started = performance.now();
    var lastProgress = started;
    var yieldEvery = 2000;

    function tick() {
        var limit = counter + yieldEvery;
        while (counter < limit) {
            var hex = sha256(challenge + counter);
            if (meetsDifficulty(hex, difficulty)) {
                var elapsed = performance.now() - started;
                self.postMessage({
                    type: 'solution',
                    solution: counter.toString(),
                    attempts: counter - startCounter + 1,
                    elapsed: elapsed
                });
                return;
            }
            counter++;
        }

        var now = performance.now();
        if (now - lastProgress >= 100) {
            self.postMessage({
                type: 'progress',
                attempts: counter - startCounter,
                elapsed: now - started
            });
            lastProgress = now;
        }

        setTimeout(tick, 0);
    }

    tick();
}

/** Measure this browser's hashing throughput over a fixed interval. */
function runBenchmark(duration) {
    duration = Math.max(500, Math.min(10000, Number(duration) || 1500));
    var challenge = '0123456789abcdef0123456789abcdef';
    var counter = 0;
    var started = performance.now();
    var lastProgress = started;

    function tick() {
        var limit = counter + 2000;
        while (counter < limit) {
            sha256(challenge + counter);
            counter++;
        }

        var now = performance.now();
        var elapsed = now - started;
        if (now - lastProgress >= 100) {
            self.postMessage({ type: 'benchmark-progress', attempts: counter, elapsed: elapsed });
            lastProgress = now;
        }

        if (elapsed >= duration) {
            self.postMessage({
                type: 'benchmark-result',
                attempts: counter,
                elapsed: elapsed,
                hashRate: counter / (elapsed / 1000)
            });
            return;
        }

        setTimeout(tick, 0);
    }

    tick();
}

/** Match PHP's whole-bit plus fractional-tenth-bit target. */
function meetsDifficulty(hex, difficulty) {
    var wholeBits = 10 + Math.floor(difficulty / 10);
    var fraction = difficulty % 10;
    var fullBytes = Math.floor(wholeBits / 8);
    var remaining = wholeBits % 8;
    var bytes = [];
    var neededBytes = fullBytes + (remaining || fraction ? 2 : 0);

    for (var i = 0; i < neededBytes; i++) {
        bytes.push(parseInt(hex.substr(i * 2, 2), 16));
    }

    for (var j = 0; j < fullBytes; j++) {
        if (bytes[j] !== 0) {
            return false;
        }
    }

    var bitOffset = fullBytes * 8;
    if (remaining > 0) {
        var mask = (0xff << (8 - remaining)) & 0xff;
        if ((bytes[fullBytes] & mask) !== 0) {
            return false;
        }
        bitOffset += remaining;
    }

    if (fraction === 0) {
        return true;
    }

    var byteIndex = Math.floor(bitOffset / 8);
    var shift = bitOffset % 8;
    var nextByte = shift === 0
        ? bytes[byteIndex]
        : (((bytes[byteIndex] << shift) & 0xff) | (bytes[byteIndex + 1] >> (8 - shift)));

    return nextByte < FRACTION_THRESHOLDS[fraction];
}

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
