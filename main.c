const crypto = require('crypto');

let g_header_b64 = null;
let g_payload_b64 = null;
let g_signature_b64 = null;
let g_to_encrypt = null;
let g_signature = null;

let g_header_b64_len = 0;
let g_payload_b64_len = 0;
let g_signature_b64_len = 0;
let g_signature_len = 0;
let g_to_encrypt_len = 0;

let g_alphabet = null;
let g_alphabet_len = 0;

let g_found_secret = null;

class ThreadData {
    constructor(startingLetter, maxLen, evpMd) {
        this.maxLen = maxLen;
        this.startingLetter = startingLetter;
        this.g_evp_md = evpMd;
        this.g_result = Buffer.alloc(crypto.getHashes()[0].length); // Assuming SHA-256
        this.g_buffer = Buffer.alloc(maxLen + 1);
    }
}

function initThreadData(data, startingLetter, maxLen, evpMd) {
    data.maxLen = maxLen;
    data.startingLetter = startingLetter;
    data.g_evp_md = evpMd;
    data.g_result = Buffer.alloc(crypto.getHashes()[0].length);
    data.g_buffer = Buffer.alloc(maxLen + 1);
}

function destroyThreadData(data) {
    // No need to free memory in JavaScript, as it is managed automatically
}

function check(data, secret) {
    if (g_found_secret !== null) {
        destroyThreadData(data);
        process.exit();
    }

    const hmac = crypto.createHmac(data.g_evp_md, secret);
    hmac.update(g_to_encrypt);
    const result = hmac.digest();

    return Buffer.compare(result, g_signature) === 0;
}

function bruteImpl(data, str, index, maxDepth) {
    for (let i = 0; i < g_alphabet_len; ++i) {
        str[index] = g_alphabet[i];

        if (index === maxDepth - 1) {
            if (check(data, str)) return true;
        } else {
            if (bruteImpl(data, str, index + 1, maxDepth)) return true;
        }
    }

    return false;
}

function bruteSequential(data) {
    data.g_buffer[0] = data.startingLetter;

    if (check(data, data.g_buffer.slice(0, 1))) {
        g_found_secret = data.g_buffer.slice(0, 1).toString();
        process.exit();
    }

    for (let i = 2; i <= data.maxLen; ++i) {
        if (bruteImpl(data, data.g_buffer, 1, i)) {
            g_found_secret = data.g_buffer.slice(0, i).toString();
            process.exit();
        }
    }
}

function usage() {
    console.log('Usage: node script.js <token> [alphabet] [max_len] [hmac_alg]');
    console.log('Defaults: alphabet=eariotnslcudpmhgbfywkvxzjqEARIOTNSLCUDPMHGBFYWKVXZJQ0123456789, max_len=6, hmac_alg=sha256');
}

function main() {
    const maxLen = 6;
    const defaultHmacAlg = 'sha256';

    g_alphabet = 'eariotnslcudpmhgbfywkvxzjqEARIOTNSLCUDPMHGBFYWKVXZJQ0123456789';

    if (process.argv.length < 3) {
        usage();
        process.exit(1);
    }

    const jwt = process.argv[2];

    if (process.argv.length > 3)
        g_alphabet = process.argv[3];

    if (process.argv.length > 4) {
        const i3 = parseInt(process.argv[4]);
        if (!isNaN(i3) && i3 > 0) {
            maxLen = i3;
        } else {
            console.log(`Invalid max_len value ${process.argv[4]} (${i3}), defaults to ${maxLen}`);
        }
    }

    const evpMd = process.argv.length > 5 ? process.argv[5] : defaultHmacAlg;

    g_alphabet_len = g_alphabet.length;

    [g_header_b64, g_payload_b64, g_signature_b64] = jwt.split('.');
    g_header_b64_len = g_header_b64.length;
    g_payload_b64_len = g_payload_b64.length;
    g_signature_b64_len = g_signature_b64.length;

    g_to_encrypt_len = g_header_b64_len + 1 + g_payload_b64_len;
    g_to_encrypt = Buffer.from(`${g_header_b64}.${g_payload_b64}`);

    g_signature_len = Buffer.from(g_signature_b64, 'base64').length;
    g_signature = Buffer.from(g_signature_b64, 'base64');

    const pointersData = new Array(g_alphabet_len);

    for (let i = 0; i < g_alphabet_len; i++) {
        pointersData[i] = new ThreadData(g_alphabet[i], maxLen, evpMd);
        initThreadData(pointersData[i], g_alphabet[i], maxLen, evpMd);
        setImmediate(bruteSequential, pointersData[i]);
    }

    if (g_found_secret === null) {
        console.log('No solution found :-(');
    } else {
        console.log(`Secret is "${g_found_secret}"`);
    }
}

main();
