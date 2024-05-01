/* Copyright (C) 2016 NooBaa */
'use strict';

const dbg = require('../util/debug_module')(__filename);
const { RpcError } = require('../rpc');
const signature_utils = require('../util/signature_utils');
const { account_cache, dn_cache } = require('./object_sdk');
const BucketSpaceNB = require('./bucketspace_nb');
const AccountSpaceFS = require('./accountspace_fs');

class AccountSDK {
    /**
     * @param {{
     *      rpc_client: nb.APIClient;
     *      internal_rpc_client: nb.APIClient;
     *      bucketspace?: nb.BucketSpace;
     * }} args
     */
    constructor({ rpc_client, internal_rpc_client, bucketspace }) {
        this.rpc_client = rpc_client;
        this.internal_rpc_client = internal_rpc_client;
        this.requesting_account = undefined;
        this.auth_token = undefined;
        this.bucketspace = bucketspace || new BucketSpaceNB({ rpc_client, internal_rpc_client });
        this.accountspace = new AccountSpaceFS({ });
    }

    set_auth_token(auth_token) {
        this.auth_token = auth_token;
        if (this.rpc_client) this.rpc_client.options.auth_token = auth_token;
    }

    get_auth_token() {
        return this.auth_token;
    }

     /**
     * @returns {nb.BucketSpace}
     */
    _get_bucketspace() {
        return this.bucketspace;
    }

    async load_requesting_account(req) {
        try {
            const token = this.get_auth_token();
            if (!token) return;
            this.requesting_account = await account_cache.get_with_cache({
                bucketspace: this._get_bucketspace(),
                access_key: token.access_key,
            });
            if (this.requesting_account?.nsfs_account_config?.distinguished_name) {
                const distinguished_name = this.requesting_account.nsfs_account_config.distinguished_name.unwrap();
                const user = await dn_cache.get_with_cache({
                    bucketspace: this._get_bucketspace(),
                    distinguished_name,
                });
                this.requesting_account.nsfs_account_config.uid = user.uid;
                this.requesting_account.nsfs_account_config.gid = user.gid;
            }
        } catch (error) {
            dbg.error('load_requesting_account error:', error);
            if (error.rpc_code) {
                if (error.rpc_code === 'NO_SUCH_ACCOUNT') throw new RpcError('INVALID_ACCESS_KEY_ID', `Account with access_key not found`);
                if (error.rpc_code === 'NO_SUCH_USER') throw new RpcError('UNAUTHORIZED', `Distinguished name associated with access_key not found`);
            } else {
                throw error;
            }
        }
    }

    // copied from function in object_sdk, sts_sdk
    async authorize_request_account(req) {
        const token = this.get_auth_token();
        // If the request is signed (authenticated)
        if (token) {
            const signature_secret = token.temp_secret_key || this.requesting_account?.access_keys?.[0]?.secret_key?.unwrap();
            const signature = signature_utils.get_signature_from_auth_token(token, signature_secret);
            if (token.signature !== signature) throw new RpcError('SIGNATURE_DOES_NOT_MATCH', `Signature that was calculated did not match`);
            return;
        }
        throw new RpcError('UNAUTHORIZED', `No permission to access`);
    }

    /**
     * @returns {nb.AccountSpace}
     */
    _get_accountspace() {
        return this.accountspace;
    }

    ////////////
    // USER   //
    ////////////

    async create_user(params, account_sdk) {
        const accountspace = this._get_accountspace();
        return accountspace.create_user(params, account_sdk);
    }

    async get_user(params, account_sdk) {
        const accountspace = this._get_accountspace();
        return accountspace.get_user(params, account_sdk);
    }

    async update_user(params, account_sdk) {
        const accountspace = this._get_accountspace();
        return accountspace.update_user(params, account_sdk);
    }

    async delete_user(params, account_sdk) {
        const accountspace = this._get_accountspace();
        return accountspace.delete_user(params, account_sdk);
    }

    async list_users(params, account_sdk) {
        const accountspace = this._get_accountspace();
        return accountspace.list_users(params, account_sdk);
    }

    ////////////////
    // ACCESS KEY //
    ////////////////

    async create_access_key(params, account_sdk) {
        const accountspace = this._get_accountspace();
        return accountspace.create_access_key(params, account_sdk);
    }

    async update_access_key(params, account_sdk) {
        const accountspace = this._get_accountspace();
        return accountspace.update_access_key(params, account_sdk);
    }

    async get_access_key_last_used(params, account_sdk) {
        const accountspace = this._get_accountspace();
        return accountspace.get_access_key_last_used(params, account_sdk);
    }

    async delete_access_key(params, account_sdk) {
        const accountspace = this._get_accountspace();
        return accountspace.delete_access_key(params, account_sdk);
    }

    async list_access_keys(params, account_sdk) {
        const accountspace = this._get_accountspace();
        return accountspace.list_access_keys(params, account_sdk);
    }
}

// EXPORTS
module.exports = AccountSDK;
