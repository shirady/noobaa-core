/* Copyright (C) 2016 NooBaa */
/* eslint max-lines: ['error', 1200] */
'use strict';

const _ = require('lodash');
const P = require('../util/promise');
const os = require('os');
const net = require('net');
const tls = require('tls');
const crypto = require('crypto');
const chance = require('chance')();
const events = require('events');

const dbg = require('../util/debug_module')(__filename);
const net_utils = require('../util/net_utils');
const FrameStream = require('../util/frame_stream');
const n2n_handshake = require('./n2n_handshake');

const CAND_TYPE_HOST = 'host';
const CAND_TYPE_PEER_REFLEX = 'peer';
const CAND_DISCARD_PORT = 0;
const CAND_TCP_TYPE_ACTIVE = 'active';
const CAND_TCP_TYPE_PASSIVE = 'passive';
const CAND_TCP_TYPE_SO = 'so';

const N2N_UFRAG_LENGTH = 32;
const N2N_PWD_LENGTH = 32;
const RAND_N2N_CHAR_POOL_64 =
    'abcdefghijklmnopqrstuvwxyz' +
    'ABCDEFGHIJKLMNOPQRTTUVWXYZ' +
    '0123456789+/';

const {
    N2N_FRAME_CONFIG,
    N2N_FRAME_HELLO,
    N2N_FRAME_HELLO_ACK,
    make_hmac_key,
    encode_handshake,
    parse_handshake,
    verify_handshake,
    connect_lookup_key,
} = n2n_handshake;

/**
 * Build a candidate key string for dedup and session pairing
 * @param {string} transport
 * @param {string} family
 * @param {string} address
 * @param {number} port
 * @returns {string}
 */
function make_candidate_key(transport, family, address, port) {
    return transport +
        (family === 'IPv6' ?
            '://[' + address + ']:' :
            '://' + address + ':') +
        port;
}

/**
 * Build a session key from local and remote candidate keys
 * @param {object} local
 * @param {object} remote
 * @returns {string}
 */
function make_session_key(local, remote) {
    return local.key + '=>' + remote.key;
}

/**
 * N2nSession tracks one local/remote candidate pair through connect states
 */
class N2nSession extends events.EventEmitter {

    constructor(local, remote) {
        super();
        this.local = local;
        this.remote = remote;
        this.key = make_session_key(local, remote);
        this.state = 'init';
        this.ready_timeout = setTimeout(() => {
            this.close(new Error('N2N SESSION TIMEOUT'));
        }, 5000);
    }

    is_init() {
        return this.state === 'init';
    }
    is_ready() {
        return this.state === 'ready';
    }
    is_closed() {
        return this.state === 'closed';
    }

    mark_checking() {
        switch (this.state) {
            case 'closed':
                throw new Error('N2N SESSION STATE CLOSED');
            case 'init':
                break;
            default:
                return;
        }
        this.state = 'checking';
    }

    mark_ready() {
        switch (this.state) {
            case 'closed':
                throw new Error('N2N SESSION STATE CLOSED');
            case 'init':
            case 'checking':
                break;
            default:
                return;
        }
        this.state = 'ready';
        clearTimeout(this.ready_timeout);
        this.ready_timeout = null;
        return true;
    }

    mark_activating() {
        switch (this.state) {
            case 'closed':
                throw new Error('N2N SESSION STATE CLOSED');
            case 'activating':
            case 'active':
                return;
            default:
                break;
        }
        this.state = 'activating';
        this.activating_timeout = setTimeout(() => {
            this.close(new Error('N2N SESSION CONNECT TIMEOUT'));
        }, 5000);
        return true;
    }

    mark_active() {
        switch (this.state) {
            case 'closed':
                throw new Error('N2N SESSION STATE CLOSED');
            case 'active':
                return;
            default:
                break;
        }
        this.state = 'active';
        clearTimeout(this.activating_timeout);
        this.activating_timeout = null;
        return true;
    }

    close(err) {
        if (this.state === 'closed') return;
        this.state = 'closed';
        this.emit('close');
        clearTimeout(this.ready_timeout);
        this.ready_timeout = null;
        clearTimeout(this.activating_timeout);
        this.activating_timeout = null;
        if (this.tcp) {
            this.tcp.destroy();
        }
    }
}

/**
 *
 * N2nConnect
 *
 * TCP+TLS node-to-node connect with a small FrameStream handshake
 * Replaces the former ICE/STUN connectivity checks under n2n://
 *
 * @param {string} connid - external id for debugging
 * @param {object} n2n_config - N2N configuration (see rpc_n2n_agent defaults)
 * @param {string} signal_target - peer address passed to signaller
 *
 */
class N2nConnect extends events.EventEmitter {

    constructor(connid, n2n_config, signal_target) {
        super();
        this.setMaxListeners(100);

        this.connid = connid;
        this.config = n2n_config;
        this.signal_target = signal_target;

        this.sessions_by_key = {};

        this.networks = [];
        _.each(os.networkInterfaces(), (interfaces, name) => {
            _.each(interfaces, n => {
                // ignore apple internal network
                if (name.startsWith('awdl')) return;
                // ignore loopback candidates for now
                if (this.config.offer_internal === false && n.internal) return;
                if (this.config.offer_ipv4 === false && n.family === 'IPv4') return;
                if (this.config.offer_ipv6 === false && n.family === 'IPv6') return;
                n.ifcname = name;
                this.networks.push(n);
                // for the nodes internal ip - add public_ips as another network interface
                if (n.address === net_utils.get_local_address() &&
                    this.config.public_ips.length) {
                    this.config.public_ips.forEach(ip => {
                        if (ip === n.address) return;
                        const public_n = _.clone(n);
                        public_n.address = ip;
                        public_n.ifcname = 'public_' + name;
                        this.networks.push(public_n);
                    });
                }
            });
        });

        this.local_credentials = {
            ufrag: random_crypto_string(
                this.config.ufrag_length || N2N_UFRAG_LENGTH,
                RAND_N2N_CHAR_POOL_64),
            pwd: random_crypto_string(
                this.config.pwd_length || N2N_PWD_LENGTH,
                RAND_N2N_CHAR_POOL_64),
        };
        this.remote_credentials = {};
        this.local_candidates = {};
        this.remote_candidates = {};

        this.on('error', err => {
            dbg.log0('N2N CONNECT CLOSE ON ERROR', err.stack || err);
            this.close();
        });
    }

    /**
     * Start controlling-side connect via signaller then candidate checks
     */
    connect() {
        // mark the connect side as controlling, which means I will be the one
        // choosing the best connection to use
        this.controlling = true;

        return P.fcall(() => {
                dbg.log3('N2N CONNECT START', this.connid);
                return this._add_local_candidates();
            })
            .then(local_info => {
                dbg.log3('N2N CONNECT LOCAL INFO', local_info.credentials,
                    _.keys(local_info.candidates), this.connid);
                return this.config.signaller(this.signal_target, local_info);
            })
            .then(remote_info => {
                dbg.log3('N2N CONNECT REMOTE INFO', remote_info.credentials,
                    _.keys(remote_info.candidates), this.connid);
                this.remote_credentials = remote_info.credentials;
                _.each(remote_info.candidates, remote_candidate => {
                    this._add_remote_candidate(remote_candidate);
                });

                setTimeout(() => {
                    this._find_session_to_activate('force');
                }, 3000);
            })
            .catch(err => {
                this.emit('error', err);
            });
    }

    /**
     * Accept peer signal info and return local credentials/candidates
     * @param {object} remote_info
     * @returns {Promise<object>}
     */
    accept(remote_info) {
        return P.fcall(() => {
                dbg.log3('N2N ACCEPT REMOTE INFO', remote_info.credentials,
                    _.keys(remote_info.candidates), this.connid);
                this.remote_credentials = remote_info.credentials;

                return this._add_local_candidates();
            })
            .then(local_info => {
                // give time for the signal response with my local credentials
                // to arrive to the connecting peer
                setTimeout(() => {
                    _.each(remote_info.candidates, remote_candidate => {
                        this._add_remote_candidate(remote_candidate);
                    });
                }, 100);

                dbg.log3('N2N ACCEPT LOCAL INFO', local_info.credentials,
                    _.keys(local_info.candidates), this.connid);
                return local_info;
            })
            .catch(err => {
                this.emit('error', err);
                throw err;
            });
    }

    /**
     * Collect local TCP candidates for signaling
     * @returns {Promise<object>}
     */
    _add_local_candidates() {
        return Promise.all([
                this._add_tcp_active_candidates(),
                this._add_tcp_permanent_passive_candidates(),
                this._add_tcp_transient_passive_candidates(),
                this._add_tcp_simultaneous_open_candidates()
            ])
            .then(() => ({
                credentials: this.local_credentials,
                candidates: this.local_candidates
            }));
    }

    /**
     * Offer active TCP candidates (outbound connect, discard port)
     */
    _add_tcp_active_candidates() {
        if (!this.config.tcp_active) return;
        _.each(this.networks, n => {
            this._add_local_candidate({
                transport: 'tcp',
                family: n.family,
                address: n.address,
                port: CAND_DISCARD_PORT,
                type: CAND_TYPE_HOST,
                tcp_type: CAND_TCP_TYPE_ACTIVE,
                ifcname: n.ifcname,
                internal: n.internal,
            });
        });
    }

    /**
     * Offer candidates on a shared permanent passive TCP listener
     * @returns {Promise}
     */
    _add_tcp_permanent_passive_candidates() {
        if (!this.config.tcp_permanent_passive) return;
        const conf = this.config.tcp_permanent_passive;

        return P.fcall(() => {
                if (!conf.connect_map) {
                    conf.connect_map = {};
                }
                const my_key = connect_lookup_key(this.local_credentials);
                conf.connect_map[my_key] = this;
                this.on('close', remove_my_from_connect_map);
                this.on('connect', remove_my_from_connect_map);

                function remove_my_from_connect_map() {
                    delete conf.connect_map[my_key];
                }

                if (!conf.connect_lookup) {
                    conf.connect_lookup = function(buffers, info) {
                        const payload = parse_handshake(buffers);
                        if (!payload) return null;
                        return conf.connect_map[payload.target_ufrag] || null;
                    };
                }

                if (!conf.listen_promise) {
                    conf.listen_promise = listen_on_port_range(conf);
                    conf.listen_promise.catch(() => {
                        conf.listen_promise = null;
                    });
                }
                return conf.listen_promise;
            })
            .then(server => {
                if (!conf.server) {
                    conf.server = server;
                    server.on('connection', conn => {
                        init_tcp_connection(conn, null, null, conf.connect_lookup);
                    });
                    server.on('close', () => {
                        conf.listen_promise = null;
                        conf.server = null;
                    });
                }
                const address = server.address();
                _.each(this.networks, n => {
                    this._add_local_candidate({
                        transport: 'tcp',
                        family: n.family,
                        address: n.address,
                        port: address.port,
                        type: CAND_TYPE_HOST,
                        tcp_type: CAND_TCP_TYPE_PASSIVE,
                        ifcname: n.ifcname,
                        internal: n.internal,
                    });
                });
            })
            .catch(err => {
                dbg.warn('N2N _add_tcp_permanent_passive_candidates: FAILED', err);
            });
    }

    /**
     * Offer candidates on a per-session transient passive listener
     * @returns {Promise}
     */
    _add_tcp_transient_passive_candidates() {
        if (!this.config.tcp_transient_passive) return;
        const conf = this.config.tcp_transient_passive;

        return listen_on_port_range(conf)
            .then(server => {
                this.on('close', close_server);
                this.on('connect', close_server);

                function close_server() {
                    server.close();
                }

                server.on('connection', conn => {
                    if (this.active_session || this.closed) {
                        conn.destroy();
                        return;
                    }
                    dbg.log3('N2N TCP ACCEPTED CONNECTION',
                        get_connection_remote_address(conn) + ':' + conn.remotePort);
                    this._init_tcp_connection(conn);
                });

                _.each(this.networks, n => {
                    this._add_local_candidate({
                        transport: 'tcp',
                        family: n.family,
                        address: n.address,
                        port: server.address().port,
                        type: CAND_TYPE_HOST,
                        tcp_type: CAND_TCP_TYPE_PASSIVE,
                        ifcname: n.ifcname,
                        internal: n.internal,
                    });
                });
            })
            .catch(err => {
                dbg.warn('N2N _add_tcp_transient_passive_candidates: FAILED', err);
            });
    }

    /**
     * Offer simultaneous-open TCP candidates
     * @returns {Promise}
     */
    _add_tcp_simultaneous_open_candidates() {
        if (!this.config.tcp_simultaneous_open) return;
        const conf = this.config.tcp_simultaneous_open;
        return P.all(_.map(this.networks, n =>
                allocate_port_in_range(conf)
                .then(port => {
                    this._add_local_candidate({
                        transport: 'tcp',
                        family: n.family,
                        address: n.address,
                        port: port,
                        type: CAND_TYPE_HOST,
                        tcp_type: CAND_TCP_TYPE_SO,
                        ifcname: n.ifcname,
                        internal: n.internal,
                    });
                })
            ))
            .catch(err => {
                dbg.warn('N2N _add_tcp_simultaneous_open_candidates: FAILED', err);
            });
    }

    /**
     * Register a local candidate and pair against remotes
     * @param {object} candidate
     */
    _add_local_candidate(candidate) {
        const local = make_candidate(candidate);
        if (this.local_candidates[local.key]) return;

        dbg.log3('N2N ADDED LOCAL CANDIDATE', local.key, this.connid);
        this.local_candidates[local.key] = local;

        _.each(this.remote_candidates, remote => {
            this._check_connectivity(local, remote);
        });
    }

    /**
     * Register a remote candidate and pair against locals
     * @param {object} candidate
     */
    _add_remote_candidate(candidate) {
        const remote = make_candidate(candidate);
        if (this.remote_candidates[remote.key]) return;

        dbg.log3('N2N ADDED REMOTE CANDIDATE', remote.key, this.connid);
        this.remote_candidates[remote.key] = remote;

        _.each(this.local_candidates, local => {
            this._check_connectivity(local, remote);
        });
    }

    /**
     * Start TCP connect for a local/remote candidate pair when applicable
     * @param {object} local
     * @param {object} remote
     */
    _check_connectivity(local, remote) {
        const session = this._add_session_if_not_exists(local, remote);
        if (!session) return;
        if (!session.is_init()) return;
        session.mark_checking();

        dbg.log3('N2N CHECKING CONNECTIVITY', session.key, this.connid);
        if (local.tcp_type === CAND_TCP_TYPE_SO) {
            this._connect_tcp_simultaneous_open_pair(session);
        } else {
            this._connect_tcp_active_passive_pair(session);
        }
    }

    /**
     * Create a session for a valid active/SO local vs remote pair
     * @param {object} local
     * @param {object} remote
     * @returns {N2nSession|undefined}
     */
    _add_session_if_not_exists(local, remote) {
        const session_key = make_session_key(local, remote);
        const existing = this.sessions_by_key[session_key];
        if (existing && !existing.is_closed()) return existing;

        if (this.config.accept_ipv4 === false && remote.family === 'IPv4') return;
        if (this.config.accept_ipv6 === false && remote.family === 'IPv6') return;
        if (local.family !== remote.family) return;
        if (local.transport !== remote.transport) return;
        if (local.transport !== 'tcp') return;
        if (local.tcp_type === CAND_TCP_TYPE_PASSIVE) return;
        if (local.tcp_type === CAND_TCP_TYPE_ACTIVE &&
            remote.tcp_type !== CAND_TCP_TYPE_PASSIVE) return;
        if (local.tcp_type === CAND_TCP_TYPE_SO &&
            remote.tcp_type !== CAND_TCP_TYPE_SO) return;

        const session = new N2nSession(local, remote);
        this.sessions_by_key[session.key] = session;
        dbg.log3('N2N ADDED SESSION', session.key, this.connid);
        return session;
    }

    /**
     * Dial remote passive candidate from local active
     * @param {N2nSession} session
     */
    _connect_tcp_active_passive_pair(session) {
        const MAX_ATTEMPTS = 10;
        let attempts = 0;
        const delay = 250;
        const try_ap = () => {
            if (this.active_session || this.closed || session.is_closed()) {
                dbg.log1('N2N TCP AP STOPPED', session.key);
                session.close(new Error('N2N TCP AP STOPPED'));
                return;
            } else if (attempts >= MAX_ATTEMPTS) {
                dbg.warn('N2N TCP AP FAILED', session.key);
                session.close(new Error('N2N TCP AP EXHAUSTED'));
                return;
            }
            session.tcp = net.connect(session.remote.port, session.remote.address);
            session.tcp.on('error', err => {
                dbg.log0('Got error', err.message);
                session.tcp.destroy();
                if (err.code === 'EHOSTUNREACH') {
                    session.close(new Error('N2N TCP AP EHOSTUNREACH'));
                    return;
                }
                setTimeout(try_ap, delay);
                attempts += 1;
            });
            session.tcp.on('connect', () => {
                dbg.log1('N2N TCP AP CONNECTED', session.key, 'took', attempts, 'attempts');
                attempts = MAX_ATTEMPTS;
                if (this.active_session || this.closed || session.is_closed()) {
                    session.tcp.destroy();
                    return;
                }
                this._init_tcp_connection(session.tcp, session);
                this._send_hello(session.tcp, session, /*use_candidate=*/ false);
            });
        };
        try_ap();
    }

    /**
     * Simultaneous-open dial for SO candidate pairs
     * @param {N2nSession} session
     */
    _connect_tcp_simultaneous_open_pair(session) {
        const MAX_ATTEMPTS = 200;
        let attempts = 0;
        let delay = 50;
        const so_connect_conf = {
            port: session.remote.port,
            address: session.remote.address,
            localPort: session.local.port
        };
        const try_so = () => {
            if (this.active_session || this.closed || session.is_closed()) {
                dbg.log1('N2N TCP SO STOPPED', session.key);
                session.close(new Error('N2N TCP SO STOPPED'));
                return;
            } else if (attempts >= MAX_ATTEMPTS) {
                dbg.warn('N2N TCP SO FAILED', session.key);
                session.close(new Error('N2N TCP SO EXHAUSTED'));
                return;
            }
            session.tcp = net.connect(so_connect_conf);
            session.tcp.on('error', err => {
                dbg.log0('Got error', err.message);
                session.tcp.destroy();
                if (err.code === 'EHOSTUNREACH') {
                    session.close(new Error('N2N TCP AP EHOSTUNREACH'));
                    return;
                }
                setTimeout(try_so, delay);
                attempts += 1;
                if (delay > 10) {
                    delay *= 0.9;
                }
            });
            session.tcp.on('connect', () => {
                dbg.log1('N2N TCP SO CONNECTED', session.key, 'took', attempts, 'attempts');
                attempts = MAX_ATTEMPTS;
                if (this.active_session || this.closed || session.is_closed()) {
                    session.tcp.destroy();
                    return;
                }
                this._init_tcp_connection(session.tcp, session);
                // prefer one HELLO exchange: only controlling sends
                if (this.controlling) {
                    this._send_hello(session.tcp, session, /*use_candidate=*/ false);
                }
            });
        };
        try_so();
    }

    /**
     * Attach this instance to a TCP connection
     * @param {net.Socket} conn
     * @param {N2nSession} [session]
     */
    _init_tcp_connection(conn, session) {
        init_tcp_connection(conn, session, this);
    }

    /**
     * Build HMAC key once both credential sets are known
     * @returns {string}
     */
    _hmac_key() {
        return make_hmac_key(this.local_credentials, this.remote_credentials);
    }

    /**
     * Send a HELLO frame on the given TCP connection
     * @param {net.Socket} conn
     * @param {N2nSession} session
     * @param {boolean} use_candidate
     */
    _send_hello(conn, session, use_candidate) {
        const body = encode_handshake({
            ufrag: this.local_credentials.ufrag,
            target_ufrag: this.remote_credentials.ufrag,
            controlling: this.controlling,
            use_candidate: use_candidate,
            address: {
                family: session.remote.family,
                address: session.remote.address,
                port: session.remote.port,
            },
        }, this._hmac_key());
        conn.frame_stream.send_message([body], N2N_FRAME_HELLO);
    }

    /**
     * Send a HELLO_ACK frame
     * @param {net.Socket} conn
     * @param {object} info
     * @param {boolean} use_candidate
     */
    _send_hello_ack(conn, info, use_candidate) {
        const body = encode_handshake({
            ufrag: this.local_credentials.ufrag,
            target_ufrag: this.remote_credentials.ufrag,
            controlling: this.controlling,
            use_candidate: use_candidate,
            address: {
                family: info.family,
                address: info.address,
                port: info.port,
            },
        }, this._hmac_key());
        conn.frame_stream.send_message([body], N2N_FRAME_HELLO_ACK);
    }

    /**
     * Handle inbound HELLO / HELLO_ACK on a TCP connection
     * @param {Buffer|Buffer[]} buffers
     * @param {number} msg_type
     * @param {object} info
     */
    _handle_handshake_frame(buffers, msg_type, info) {
        if (this.closed) {
            this._bad_handshake(info, 'PACKET ON CLOSED N2N CONNECT');
            return;
        }
        if (!this.remote_credentials || !this.remote_credentials.ufrag) {
            this._bad_handshake(info, 'HANDSHAKE BEFORE REMOTE CREDENTIALS');
            return;
        }

        const payload = parse_handshake(buffers);
        if (!payload) {
            this._bad_handshake(info, 'HANDSHAKE PARSE FAILED');
            return;
        }
        if (!verify_handshake(payload, this._hmac_key())) {
            this._bad_handshake(info, 'HANDSHAKE BAD HMAC');
            return;
        }
        if (payload.target_ufrag !== this.local_credentials.ufrag ||
            payload.ufrag !== this.remote_credentials.ufrag) {
            this._bad_handshake(info, 'HANDSHAKE BAD UFRAG');
            return;
        }
        if ((payload.controlling && this.controlling) ||
            (!payload.controlling && !this.controlling)) {
            this._bad_handshake(info, 'HANDSHAKE BAD CONTROLLING STATE');
            return;
        }

        if (msg_type === N2N_FRAME_HELLO) {
            this._handle_hello(payload, info);
        } else if (msg_type === N2N_FRAME_HELLO_ACK) {
            this._handle_hello_ack(payload, info);
        } else {
            this._bad_handshake(info, 'HANDSHAKE UNEXPECTED TYPE ' + msg_type);
        }
    }

    /**
     * Process peer HELLO: bind session, mark ready, optionally activate, ACK
     * @param {object} payload
     * @param {object} info
     */
    _handle_hello(payload, info) {
        dbg.log3('N2N HELLO FROM', info.key);

        if (!payload.address) {
            this._bad_handshake(info, 'HELLO MISSING ADDRESS');
            return;
        }

        if (!info.session) {
            info.session = this._add_session_if_not_exists(make_candidate({
                transport: info.transport,
                family: info.family,
                address: payload.address.address,
                port: payload.address.port,
                type: CAND_TYPE_PEER_REFLEX,
            }), make_candidate({
                transport: info.transport,
                family: info.family,
                address: info.address,
                port: info.port,
                type: CAND_TYPE_PEER_REFLEX,
            }));
        }
        if (info.session) {
            if (info.tcp && !info.tcp.destroyed &&
                (!info.session.tcp || info.session.tcp.destroyed)) {
                info.session.tcp = info.tcp;
            }
            if (info.session.mark_ready()) {
                dbg.log3('N2N SESSION READY (HELLO)', info.session.key, this.connid);
                this._find_session_to_activate();
            }
            if (payload.use_candidate) {
                this._activate_session_complete(info.session);
            }
        }

        this._send_hello_ack(info.tcp, info, payload.use_candidate);
    }

    /**
     * Process peer HELLO_ACK: mark ready and optionally complete activate
     * @param {object} payload
     * @param {object} info
     */
    _handle_hello_ack(payload, info) {
        dbg.log3('N2N HELLO_ACK FROM', info.key);

        if (!payload.address) {
            this._bad_handshake(info, 'HELLO_ACK MISSING ADDRESS');
            return;
        }

        let session = info.session;
        if (!session) {
            // match by remote key from the TCP peer address
            session = _.find(this.sessions_by_key, s =>
                s.remote && s.remote.key === info.key && !s.is_closed());
            info.session = session;
        }
        if (!session || session.is_closed()) {
            this._bad_handshake(info, 'HELLO_ACK FOR MISSING SESSION');
            return;
        }

        let changed = false;
        if (session.mark_ready()) {
            dbg.log3('N2N SESSION READY (ACK)', session.key, this.connid);
            changed = true;
        }
        if (changed) {
            this._find_session_to_activate();
        }
        if (payload.use_candidate) {
            this._activate_session_complete(session);
        }
    }

    /**
     * Destroy TCP on bad handshake
     * @param {object} info
     * @param {string} reason
     */
    _bad_handshake(info, reason) {
        dbg.warn('N2N _bad_handshake:', reason, info.key, this.connid);
        if (info.tcp) info.tcp.destroy();
    }

    /**
     * Controlling side: pick best ready session (by remote priority)
     * @param {boolean|string} [force]
     */
    _find_session_to_activate(force) {
        if (this.closed) return;
        if (!this.controlling) return;

        let best_session;
        let highest_non_closed_priority = -Infinity;

        _.each(this.sessions_by_key, session => {
            if (session.is_closed()) return;
            if (session.remote.priority > highest_non_closed_priority) {
                highest_non_closed_priority = session.remote.priority;
            }
            if (!session.is_ready()) return;
            if (best_session) {
                if (session.remote.priority === best_session.remote.priority) {
                    if (session.key > best_session.key) {
                        best_session = session;
                    }
                } else if (session.remote.priority > best_session.remote.priority) {
                    best_session = session;
                }
            } else {
                best_session = session;
            }
        });

        if (best_session &&
            (force || highest_non_closed_priority <= best_session.remote.priority)) {
            this._activate_session(best_session);
        }
    }

    /**
     * Controlling side: send HELLO with use_candidate to select the session
     * @param {N2nSession} session
     */
    _activate_session(session) {
        if (this.closed) return;
        if (this.activating_session) return;
        this.activating_session = session;

        dbg.log3('N2N SESSION ACTIVATING', session.key);
        session.mark_activating();

        if (session.tcp) {
            this._send_hello(session.tcp, session, /*use_candidate=*/ true);
        }
    }

    /**
     * Mark session active, close others, optionally upgrade to TLS
     * @param {N2nSession} session
     */
    _activate_session_complete(session) {
        if (this.closed) return;
        if (this.active_session) return;
        dbg.log3('N2N SESSION ACTIVE', session.key);
        this.active_session = session;
        session.mark_active();
        session.on('close', () => {
            this.close();
        });
        _.each(this.sessions_by_key, s => {
            if (s !== session) {
                s.close();
            }
        });
        if (session.tcp && this.config.tcp_tls) {
            // allow HELLO_ACK to flush before TLS kicks in
            setImmediate(() => {
                this._upgrade_to_tls(session);
            });
        } else {
            this.emit('connect', session);
        }
    }

    /**
     * Upgrade the active TCP session to TLS
     * @param {N2nSession} session
     */
    _upgrade_to_tls(session) {
        dbg.log1('N2N UPGRADE TO TLS', session.key, session.state);
        const tcp_conn = session.tcp;
        let tls_conn;
        const ssl_options = { honorCipherOrder: true, ...this.config.ssl_options };
        if (this.controlling) {
            ssl_options.socket = tcp_conn;
            tls_conn = tls.connect(ssl_options);
        } else {
            ssl_options.isServer = true;
            tls_conn = new tls.TLSSocket(tcp_conn, ssl_options);
        }
        tls_conn.on('secure', once_connected);
        tls_conn.on('error', destroy_conn);
        tls_conn.on('close', destroy_conn);

        function destroy_conn(err) {
            if (err) {
                dbg.log0('TLS ERROR:', session.key, err);
            } else {
                dbg.log0('TLS CLOSED:', session.key);
            }
            session.close(err);
        }

        const self = this;

        function once_connected() {
            dbg.log3('N2N TLS CONNECTED', session.key, tls_conn.getCipher());
            session.tcp = tls_conn;
            tls_conn.frame_stream = new FrameStream(tls_conn);
            self.emit('connect', session);
        }
    }

    /**
     * Close all sessions and emit close
     */
    close() {
        if (this.closed) return;
        this.closed = true;
        this.emit('close');
        _.each(this.sessions_by_key, session => {
            session.close();
        });
    }
}

/**
 * using crypto random to avoid predictability
 */
function random_crypto_string(len, char_pool) {
    let str = '';
    const bytes = crypto.randomBytes(len);
    for (let i = 0; i < len; ++i) {
        str += char_pool[bytes[i] % char_pool.length];
    }
    return str;
}

/**
 * init_tcp_connection
 *
 * used for both per-instance sockets and the shared permanent passive server
 * (hence the optional connect_lookup)
 */
function init_tcp_connection(conn, session, n2n, connect_lookup) {
    const info = {
        family: conn.remoteFamily,
        address: get_connection_remote_address(conn),
        port: conn.remotePort,
        key: make_candidate_key('tcp', conn.remoteFamily, get_connection_remote_address(conn), conn.remotePort),
        tcp: conn,
        transport: 'tcp',
        session: session,
    };

    let temp_queue = [];

    if (n2n) {
        n2n.on('close', destroy_conn);
    }
    conn.on('close', destroy_conn);
    conn.on('error', destroy_conn);
    conn.on('timeout', destroy_conn);

    function destroy_conn(err) {
        temp_queue = null;
        conn.destroy();
        if (info.session) {
            info.session.close(err || new Error('N2N TCP DESTROYING'));
        } else {
            dbg.log1('N2N TCP DESTROYING', err || '');
        }
    }

    // queue RPC messages until a 'message' listener is installed
    conn.on('newListener', function new_listener_handler(event) {
        if (event !== 'message') return;
        dbg.log1('N2N TCP UNLEASH', temp_queue.length, 'QUEUED MESSAGES', info.key);
        conn.removeListener('newListener', new_listener_handler);
        const mq = temp_queue;
        temp_queue = null;
        for (let i = 0; i < mq.length; ++i) {
            conn.emit('message', mq[i]);
        }
    });

    conn.frame_stream = new FrameStream(conn, (buffers, msg_type) => {
        if (msg_type === N2N_FRAME_HELLO || msg_type === N2N_FRAME_HELLO_ACK) {
            if (!n2n) {
                n2n = connect_lookup(buffers, info);
                if (!n2n) {
                    destroy_conn(new Error('N2N LOOKUP FAILED'));
                    return;
                }
                n2n.on('close', destroy_conn);
            }
            n2n._handle_handshake_frame(buffers, msg_type, info);
            return;
        }
        if (!temp_queue) {
            conn.emit('message', buffers);
            return;
        }
        if (temp_queue.length > 30) {
            destroy_conn(new Error('N2N TCP TOO MANY QUEUED MESSAGES'));
            return;
        }
        temp_queue.push(buffers);
        dbg.log1('N2N TCP HOLDING MESSAGE IN QUEUE FOR LISTENER',
            temp_queue.length, info.key);
    }, N2N_FRAME_CONFIG);
}

/**
 * Annotate candidate with key and priority
 * @param {object} cand
 * @returns {object}
 */
function make_candidate(cand) {
    const is_private_no_throw = address => {
        try {
            return net_utils.is_private(address);
        } catch (err) {
            return false;
        }
    };
    cand.key = make_candidate_key(cand.transport, cand.family, cand.address, cand.port);
    cand.priority =
        (is_private_no_throw(cand.address) ? 1000 : 0) +
        (cand.transport === 'tcp' ? 100 : 0) +
        (cand.tcp_type === CAND_TCP_TYPE_SO ? 0 : 1);
    return cand;
}

/**
 * Listen on a TCP port (random or in range) and return the server
 * @param {number|object} port_range
 * @returns {Promise<net.Server>}
 */
function listen_on_port_range(port_range) {
    let attempts = 0;
    let max_attempts = 3;
    return P.fcall(try_to_listen);

    function try_to_listen() {
        let port;
        const server = net.createServer();
        if (typeof(port_range) === 'object') {
            if (typeof(port_range.min) === 'number' &&
                typeof(port_range.max) === 'number') {
                max_attempts = Math.min(10, 10 * (port_range.max - port_range.min));
                port = chance.integer(port_range);
            } else {
                port = port_range.port || 0;
            }
        } else if (typeof(port_range) === 'number') {
            port = port_range;
        } else {
            // can't use port 0 inside node cluster (same port for all workers)
            port = chance.integer({
                min: 1025,
                max: 64 * 1024,
            });
        }
        if (attempts > max_attempts) {
            throw new Error('N2N PORT ALLOCATION EXHAUSTED');
        }
        dbg.log3('N2N listen_on_port_range', port, 'attempts', attempts);
        attempts += 1;
        server.listen(port);
        return events.once(server, 'listening')
            .then(() => server)
            .catch(err => {
                dbg.log1('N2N listen_on_port_range: FAILED', port, err);
                server.close();
                return P.delay(1).then(try_to_listen);
            });
    }
}

/**
 * Allocate then release a port in range, return the number
 * @param {number|object} port_range
 * @returns {Promise<number>}
 */
function allocate_port_in_range(port_range) {
    return listen_on_port_range(port_range)
        .then(server => {
            const port = server.address().port;
            server.close();
            return port;
        });
}

/**
 * Remote address without link-local suffix (e.g. %eth0)
 * @param {net.Socket} conn
 * @returns {string}
 */
function get_connection_remote_address(conn) {
    const ip = conn.remoteAddress;
    return ip.split('%')[0];
}

module.exports = N2nConnect;
