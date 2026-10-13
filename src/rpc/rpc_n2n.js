/* Copyright (C) 2016 NooBaa */
'use strict';

const dbg = require('../util/debug_module')(__filename);
const RpcBaseConnection = require('./rpc_base_conn');
const n2n_wss = require('./n2n_wss');

/**
 *
 * RpcN2NConnection
 *
 * n2n - node-to-node or noobaa-to-noobaa, essentially p2p, but noobaa branded.
 * Transport is WSS: peers exchange listen endpoints over n2n_signal, then dial wss://.
 *
 */
class RpcN2NConnection extends RpcBaseConnection {

    constructor(addr_url, n2n_agent) {
        if (!n2n_agent) throw new Error('N2N AGENT NOT REGISTERED');
        super(addr_url);
        this.n2n_agent = n2n_agent;

        this.reset_n2n_listener = () => {
            const reset_err = new Error('N2N RESET');
            reset_err.stack = '';
            this.emit('error', reset_err);
        };
        n2n_agent.on('reset_n2n', this.reset_n2n_listener);
    }

    /**
     * Start dialer-side WSS connect via n2n_signal
     */
    _connect() {
        this.controlling = true;
        n2n_wss.connect(this).catch(err => this.emit('error', err));
    }

    /**
     * Accept remote signal info and return local WSS endpoints for the reply
     * @param {object} remote_info
     * @returns {{ session_id: string, endpoints: string[] }}
     */
    accept(remote_info) {
        return n2n_wss.accept(this, remote_info);
    }

    /**
     * Close the WSS transport and unregister reset listener
     * @param {Error} [err]
     */
    _close(err) {
        dbg.log0('_close', err);
        this.n2n_agent.removeListener('reset_n2n', this.reset_n2n_listener);
        this.n2n_agent.unregister_pending_session_for_conn(this);
        n2n_wss.close(this);
    }

    async _send(msg) {
        // overridden by n2n_wss.bind_ws once the WebSocket is connected
        throw new Error('N2N NOT CONNECTED');
    }

}


module.exports = RpcN2NConnection;
