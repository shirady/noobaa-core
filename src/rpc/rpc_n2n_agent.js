/* Copyright (C) 2016 NooBaa */
'use strict';

const _ = require('lodash');
const tls = require('tls');
const WS = require('ws');

const dbg = require('../util/debug_module')(__filename);
const config = require('../../config');
const url_utils = require('../util/url_utils');
const ssl_utils = require('../util/ssl_utils');
const EventEmitter = require('events').EventEmitter;
const RpcN2NConnection = require('./rpc_n2n');
const n2n_wss = require('./n2n_wss');

const N2N_STAR = 'n2n://*';
const N2N_CONFIG_PORT_PICK = ['min', 'max', 'port'];
// Legacy ICE/TCP fields are still picked for agent_info / system sync compatibility
// but are unused by the WSS transport path.
const N2N_CONFIG_FIELDS_PICK = [
    'offer_ipv4',
    'offer_ipv6',
    'accept_ipv4',
    'accept_ipv6',
    'offer_internal',
    'tcp_active',
    'tcp_permanent_passive',
    'tcp_transient_passive',
    'tcp_simultaneous_open',
    'tcp_tls',
    'udp_port',
    'udp_dtls',
    'stun_servers',
    'public_ips'
];

const PENDING_SESSION_TIMEOUT_MS = 30 * 1000;

/**
 *
 * RpcN2NAgent
 *
 * represents an end-point for N2N connections.
 * it will be used to accept new connections initiated by remote peers,
 * and also when initiated locally to connect to a remote peer.
 *
 * Transport is WSS: this agent listens with HTTPS+WSS and advertises
 * wss:// endpoints over the existing n2n_signal relay.
 *
 */

class RpcN2NAgent extends EventEmitter {

    constructor(options) {
        super();
        options = options || {};

        // we expect all n2n connections to register on the agent n2n_reset event
        this.setMaxListeners(100);

        // send_signal is function(info) that sends over a signal channel
        // and delivers the info to info.target,
        // and returns back the info that was returned by the peer.
        const send_signal = options.send_signal;

        this._pending_sessions = new Map();

        // initialize the default config structure
        // Legacy tcp_*/udp_*/stun_* keys are tolerated when synced from the system
        // but are not used for connecting (WSS listen port is set via start_wss_server).
        this.n2n_config = {

            // ip options
            offer_ipv4: true,
            offer_ipv6: true,
            accept_ipv4: true,
            accept_ipv6: true,
            offer_internal: config.N2N_OFFER_INTERNAL,

            // legacy tcp options (unused by WSS path, kept for config sync)
            tcp_active: true,
            tcp_permanent_passive: {
                min: 60101, //60100 is used by the hosted agents
                max: 60600
            },
            tcp_transient_passive: false,
            tcp_simultaneous_open: false,
            tcp_tls: true,

            // legacy udp options (unused by WSS path)
            udp_port: true,
            udp_dtls: false,

            // legacy stun (unused by WSS path)
            stun_servers: [],

            public_ips: [],

            // ssl options - applied when agent sets certificate via set_ssl_context
            ssl_options: {
                // we allow self generated certificates to avoid public CA signing:
                rejectUnauthorized: false,
                secureContext: tls.createSecureContext({ honorCipherOrder: true, ...ssl_utils.generate_ssl_certificate() }),
            },

            // signaller callback
            // send connect info to the peer over a relayed signal channel
            // in order to exchange WSS listen endpoints.
            signaller: (target, info) => send_signal({
                source: this.rpc_address,
                target: target,
                info: info
            })
        };
    }

    /**
     * Set this agent's n2n:// RPC address
     * @param {string} rpc_address
     */
    set_rpc_address(rpc_address) {
        dbg.log('set_rpc_address:', rpc_address, 'was', this.rpc_address);
        this.rpc_address = rpc_address;
    }

    /**
     * Clear the RPC address
     */
    reset_rpc_address() {
        this.set_rpc_address('');
    }

    /**
     * Accept signals for any n2n target (testing / local agent)
     */
    set_any_rpc_address() {
        this.set_rpc_address(N2N_STAR);
    }

    /**
     * Update SSL secure context params (certificate) on the n2n config
     * @param {object} secure_context_params
     */
    set_ssl_context(secure_context_params) {
        this.n2n_config.ssl_options.secureContext =
            tls.createSecureContext({ ...secure_context_params, honorCipherOrder: true });
    }

    /**
     * Apply n2n_config updates from the system. Legacy ICE/TCP keys are stored
     * but ignored by the WSS transport. Local wss_port is preserved.
     * @param {object} n2n_config
     */
    update_n2n_config(n2n_config) {
        dbg.log0('UPDATE N2N CONFIG', n2n_config);
        const wss_port = this.n2n_config.wss_port;
        _.each(n2n_config, (val, key) => {
            if (key === 'wss_port') return;
            if (key === 'tcp_permanent_passive' && _.isObject(val)) {
                // store port-range fields only (no TCP listener)
                this.n2n_config.tcp_permanent_passive = _.pick(val, N2N_CONFIG_PORT_PICK);
            } else {
                this.n2n_config[key] = val;
            }
        });
        if (wss_port) this.n2n_config.wss_port = wss_port;

        // emit 'reset_n2n' to notify all existing connections to close
        this.emit('reset_n2n');
        const remaining_listeners = this.listenerCount('reset_n2n');
        if (remaining_listeners) {
            dbg.warn('update_n2n_config: remaining listeners on reset_n2n event',
                remaining_listeners, '(probably a connection that forgot to call close)');
        }
    }

    /**
     * Stop the dedicated N2N WSS server and cancel pending accept sessions
     */
    disconnect() {
        this.stop_wss_server();
    }

    /**
     * Start a dedicated WS server on the given HTTP(S) server for N2N accept.
     * Does not use register_ws_transport so normal wss:// agents are unaffected.
     * @param {import('http').Server|import('https').Server} http_server
     * @param {number|string} port
     */
    start_wss_server(http_server, port) {
        this.stop_wss_server();
        this.n2n_config.wss_port = Number(port);
        this._ws_server = new WS.Server({
            server: http_server,
            perMessageDeflate: false,
        });
        this._ws_server.on('connection', (ws, req) => this._on_wss_connection(ws, req));
        this._ws_server.on('error', err => {
            dbg.error('N2N WSS SERVER ERROR', err.stack || err);
        });
        dbg.log0('N2N WSS SERVER STARTED on port', this.n2n_config.wss_port);
    }

    /**
     * Stop the N2N WSS server and clear pending sessions
     */
    stop_wss_server() {
        if (this._ws_server) {
            try {
                this._ws_server.close();
            } catch (err) {
                dbg.warn('N2N WSS SERVER CLOSE ERROR', err.message || err);
            }
            this._ws_server = null;
        }
        for (const [session_id, entry] of this._pending_sessions) {
            clearTimeout(entry.timer);
            const err = new Error('N2N WSS PENDING CANCELLED');
            err.stack = '';
            entry.conn.emit('error', err);
            this._pending_sessions.delete(session_id);
        }
        delete this.n2n_config.wss_port;
    }

    /**
     * Register a pending accept-side connection waiting for inbound WSS
     * @param {string} session_id
     * @param {RpcN2NConnection} conn
     */
    register_pending_session(session_id, conn) {
        this.unregister_pending_session_for_conn(conn);
        const timer = setTimeout(() => {
            const entry = this._pending_sessions.get(session_id);
            if (!entry || entry.conn !== conn) return;
            this._pending_sessions.delete(session_id);
            const err = new Error('N2N WSS ACCEPT TIMEOUT');
            err.stack = '';
            conn.emit('error', err);
        }, PENDING_SESSION_TIMEOUT_MS);
        this._pending_sessions.set(session_id, { conn, timer });
    }

    /**
     * Remove any pending session entry for this connection
     * @param {RpcN2NConnection} conn
     */
    unregister_pending_session_for_conn(conn) {
        for (const [session_id, entry] of this._pending_sessions) {
            if (entry.conn === conn) {
                clearTimeout(entry.timer);
                this._pending_sessions.delete(session_id);
            }
        }
    }

    /**
     * Claim an inbound WSS socket by session_id and finish accept-side connect
     * @param {import('ws')} ws
     * @param {import('http').IncomingMessage} req
     */
    _on_wss_connection(ws, req) {
        const session_id = n2n_wss.parse_session_id_from_req_url(req.url);
        const entry = session_id && this._pending_sessions.get(session_id);
        if (!entry) {
            dbg.warn('N2N WSS ACCEPT UNKNOWN SESSION', session_id, req.url);
            close_ws(ws);
            return;
        }
        clearTimeout(entry.timer);
        this._pending_sessions.delete(session_id);
        const conn = entry.conn;
        try {
            dbg.log0('N2N WSS ACCEPT CONNECTION', conn.connid, 'session', session_id);
            n2n_wss.bind_ws(conn, ws);
            conn.emit('connect');
        } catch (err) {
            dbg.error('N2N WSS ACCEPT ERROR', err.stack || err);
            close_ws(ws);
            conn.emit('error', err);
        }
    }

    /**
     * Plain n2n_config for agent_info reporting (includes legacy unused keys)
     * @returns {object}
     */
    get_plain_n2n_config() {
        const n2n_config =
            _.pick(this.n2n_config, N2N_CONFIG_FIELDS_PICK);
        n2n_config.tcp_permanent_passive =
            n2n_config.tcp_permanent_passive ?
            _.pick(n2n_config.tcp_permanent_passive, N2N_CONFIG_PORT_PICK) :
            n2n_config.tcp_permanent_passive;
        return n2n_config;
    }

    /**
     * Handle an inbound n2n_signal: create pending connection and return local WSS info
     * @param {object} params
     * @returns {{ session_id: string, endpoints: string[] }}
     */
    accept_signal(params) {
        dbg.log1('N2N AGENT accept_signal:', params, 'my rpc_address', this.rpc_address);

        // target address is me, source is you.
        // the special case if rpc_address='n2n://*' allows testing code to accept for any target
        const source = url_utils.quick_parse(params.source);
        const target = url_utils.quick_parse(params.target);
        if (!this.rpc_address || !target ||
            (this.rpc_address !== N2N_STAR && this.rpc_address !== target.href)) {
            throw new Error('N2N MISMATCHING PEER ID ' + params.target +
                ' my rpc_address ' + this.rpc_address);
        }
        const conn = new RpcN2NConnection(source, this);
        conn.once('connect', () => this.emit('connection', conn));
        return conn.accept(params.info);
    }


}

/**
 * Close a WebSocket if it is still open
 * @param {import('ws')} ws
 */
function close_ws(ws) {
    if (ws &&
        ws.readyState !== WS.CLOSED &&
        ws.readyState !== WS.CLOSING) {
        ws.close();
    }
}

module.exports = RpcN2NAgent;
