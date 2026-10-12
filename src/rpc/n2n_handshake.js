/* Copyright (C) 2016 NooBaa */
'use strict';

const crypto = require('crypto');
const config = require('../../config');
const buffer_utils = require('../util/buffer_utils');

/**
 * N2N pre-TLS handshake over FrameStream
 * Replaces the former ICE/STUN binding on shared TCP listeners
 */

const N2N_FRAME_CONFIG = {
    magic: 'N2Bmagic',
    // maximum frame size allows a full object part to be sent plus some change
    max_len: config.MAX_OBJECT_PART_SIZE + (1024 * 1024),
};

const N2N_FRAME_HELLO = 1;
const N2N_FRAME_HELLO_ACK = 2;

/**
 * Build a stable HMAC key from both peers' credentials
 * @param {{ufrag: string, pwd: string}} cred_a
 * @param {{ufrag: string, pwd: string}} cred_b
 * @returns {string}
 */
function make_hmac_key(cred_a, cred_b) {
    const [first, second] = [cred_a, cred_b].sort((a, b) => a.ufrag.localeCompare(b.ufrag));
    return first.ufrag + first.pwd + second.ufrag + second.pwd;
}

/**
 * Compute HMAC for a handshake payload (excludes hmac field itself)
 * @param {object} payload
 * @param {string} hmac_key
 * @returns {string} base64 hmac
 */
function compute_hmac(payload, hmac_key) {
    const addr = payload.address || {};
    const data = [
        payload.ufrag || '',
        payload.target_ufrag || '',
        payload.controlling ? '1' : '0',
        payload.use_candidate ? '1' : '0',
        addr.family || '',
        addr.address || '',
        String(addr.port || 0),
    ].join(':');
    return crypto.createHmac('sha256', hmac_key).update(data).digest('base64');
}

/**
 * Encode a HELLO or HELLO_ACK frame body as a Buffer
 * @param {object} fields
 * @param {string} hmac_key
 * @returns {Buffer}
 */
function encode_handshake(fields, hmac_key) {
    const payload = {
        ufrag: fields.ufrag,
        target_ufrag: fields.target_ufrag,
        controlling: Boolean(fields.controlling),
        use_candidate: Boolean(fields.use_candidate),
        address: fields.address,
    };
    payload.hmac = compute_hmac(payload, hmac_key);
    return Buffer.from(JSON.stringify(payload), 'utf8');
}

/**
 * Parse handshake JSON without verifying HMAC (needed for shared-listener lookup)
 * @param {Buffer|Buffer[]} buffers
 * @returns {object|null}
 */
function parse_handshake(buffers) {
    try {
        const buf = Buffer.isBuffer(buffers) ? buffers : buffer_utils.join(buffers);
        const payload = JSON.parse(buf.toString('utf8'));
        if (!payload || typeof payload !== 'object') return null;
        if (!payload.ufrag || !payload.target_ufrag || !payload.hmac) return null;
        return payload;
    } catch (err) {
        return null;
    }
}

/**
 * Verify HMAC on a parsed handshake payload
 * @param {object} payload
 * @param {string} hmac_key
 * @returns {boolean}
 */
function verify_handshake(payload, hmac_key) {
    try {
        const expected = compute_hmac(payload, hmac_key);
        const a = Buffer.from(payload.hmac);
        const b = Buffer.from(expected);
        if (a.length !== b.length) return false;
        return crypto.timingSafeEqual(a, b);
    } catch (err) {
        return false;
    }
}

/**
 * Parse and verify a handshake frame body
 * @param {Buffer|Buffer[]} buffers
 * @param {string} hmac_key
 * @returns {object|null} payload or null if invalid
 */
function decode_handshake(buffers, hmac_key) {
    const payload = parse_handshake(buffers);
    if (!payload) return null;
    if (!verify_handshake(payload, hmac_key)) return null;
    return payload;
}

/**
 * Lookup key for the shared passive server map (accept side ufrag)
 * @param {{ufrag: string}} credentials
 * @returns {string}
 */
function connect_lookup_key(credentials) {
    return credentials.ufrag;
}

exports.N2N_FRAME_CONFIG = N2N_FRAME_CONFIG;
exports.N2N_FRAME_HELLO = N2N_FRAME_HELLO;
exports.N2N_FRAME_HELLO_ACK = N2N_FRAME_HELLO_ACK;
exports.make_hmac_key = make_hmac_key;
exports.compute_hmac = compute_hmac;
exports.encode_handshake = encode_handshake;
exports.parse_handshake = parse_handshake;
exports.verify_handshake = verify_handshake;
exports.decode_handshake = decode_handshake;
exports.connect_lookup_key = connect_lookup_key;
