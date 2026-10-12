/* Copyright (C) 2016 NooBaa */
'use strict';

const n2n_handshake = require('../../../rpc/n2n_handshake');

const {
    make_hmac_key,
    encode_handshake,
    parse_handshake,
    verify_handshake,
    decode_handshake,
    connect_lookup_key,
} = n2n_handshake;

describe('n2n_handshake', () => {

    const cred_a = { ufrag: 'aaaUfrag01234567890123456789012', pwd: 'aaaPwd0123456789012345678901234' };
    const cred_b = { ufrag: 'bbbUfrag01234567890123456789012', pwd: 'bbbPwd0123456789012345678901234' };

    const base_fields = {
        ufrag: cred_a.ufrag,
        target_ufrag: cred_b.ufrag,
        controlling: true,
        use_candidate: false,
        address: {
            family: 'IPv4',
            address: '127.0.0.1',
            port: 60101,
        },
    };

    it('make_hmac_key is order-independent', () => {
        expect(make_hmac_key(cred_a, cred_b)).toBe(make_hmac_key(cred_b, cred_a));
    });

    it('encode/decode round-trip accepts valid hmac', () => {
        const key = make_hmac_key(cred_a, cred_b);
        const buf = encode_handshake(base_fields, key);
        const payload = decode_handshake(buf, key);
        expect(payload).toMatchObject({
            ufrag: cred_a.ufrag,
            target_ufrag: cred_b.ufrag,
            controlling: true,
            use_candidate: false,
        });
    });

    it('verify rejects tampered payload', () => {
        const key = make_hmac_key(cred_a, cred_b);
        const buf = encode_handshake(base_fields, key);
        const payload = parse_handshake(buf);
        payload.use_candidate = true;
        expect(verify_handshake(payload, key)).toBe(false);
    });

    it('verify rejects wrong hmac key', () => {
        const key = make_hmac_key(cred_a, cred_b);
        const wrong_key = make_hmac_key(cred_a, { ufrag: cred_b.ufrag, pwd: 'wrong' });
        const buf = encode_handshake(base_fields, key);
        expect(decode_handshake(buf, wrong_key)).toBeNull();
    });

    it('parse allows lookup before verify', () => {
        const key = make_hmac_key(cred_a, cred_b);
        const buf = encode_handshake(base_fields, key);
        const payload = parse_handshake(buf);
        expect(payload.target_ufrag).toBe(cred_b.ufrag);
        expect(connect_lookup_key(cred_b)).toBe(cred_b.ufrag);
    });

    it('parse rejects non-json', () => {
        expect(parse_handshake(Buffer.from('not-json'))).toBeNull();
    });
});
