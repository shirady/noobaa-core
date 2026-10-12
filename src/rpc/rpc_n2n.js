/* Copyright (C) 2016 NooBaa */
'use strict';

const dbg = require('../util/debug_module')(__filename);
const RpcBaseConnection = require('./rpc_base_conn');
const N2nConnect = require('./n2n_connect');

/**
 *
 * RpcN2NConnection
 *
 * n2n - node-to-node or noobaa-to-noobaa, essentially p2p, but noobaa branded.
 *
 */
class RpcN2NConnection extends RpcBaseConnection {

    constructor(addr_url, n2n_agent) {
        if (!n2n_agent) throw new Error('N2N AGENT NOT REGISTERED');
        super(addr_url);
        this.n2n_agent = n2n_agent;
        this.n2n = new N2nConnect(this.connid, n2n_agent.n2n_config, this.url.href);

        this.n2n.on('close', () => {
            const closed_err = new Error('N2N CONNECT CLOSED');
            closed_err.stack = '';
            this.emit('error', closed_err);
        });

        this.n2n.on('error', err => this.emit('error', err));

        this.reset_n2n_listener = () => {
            const reset_err = new Error('N2N RESET');
            reset_err.stack = '';
            this.emit('error', reset_err);
        };
        n2n_agent.on('reset_n2n', this.reset_n2n_listener);

        this.n2n.once('connect', session => {
            this.session = session;
            if (!session.tcp) {
                this.emit('error', new Error('N2N CONNECTED WITHOUT TCP SESSION'));
                return;
            }
            dbg.log1('N2N CONNECTED TO TCP',
                session.tcp.remoteAddress + ':' + session.tcp.remotePort);
            this._send = async msg => session.tcp.frame_stream.send_message(msg);
            session.tcp.on('message', msg => this.emit('message', msg));
            this.emit('connect');
        });
    }

    /**
     * Initiate outbound N2N connect (controlling side)
     */
    _connect() {
        this.controlling = true;
        return this.n2n.connect();
    }

    /**
     * Pass remote_info to N2nConnect and return local info for the signaller reply
     * @param {object} remote_info
     * @returns {Promise<object>}
     */
    accept(remote_info) {
        return this.n2n.accept(remote_info);
    }

    /**
     * Close the underlying N2N connect instance
     * @param {Error} [err]
     */
    _close(err) {
        dbg.log0('_close', err);
        this.n2n_agent.removeListener('reset_n2n', this.reset_n2n_listener);
        this.n2n.close();
    }

    async _send(msg) {
        // overridden once n2n emit's connect
        throw new Error('N2N NOT CONNECTED');
    }

}


module.exports = RpcN2NConnection;
