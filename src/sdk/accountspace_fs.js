/* Copyright (C) 2024 NooBaa */
'use strict';

const _ = require('lodash');
const path = require('path');
const config = require('../../config');
const dbg = require('../util/debug_module')(__filename);
const P = require('../util/promise');
const nb_native = require('../util/nb_native');
const native_fs_utils = require('../util/native_fs_utils');
const { CONFIG_SUBDIRS } = require('../manage_nsfs/manage_nsfs_constants');
const { create_arn, IAM_DEFAULT_PATH, get_action_message_title,
    check_iam_path_was_set, MAX_NUMBER_OF_ACCESS_KEYS,
    access_key_status_enum, identity_enum } = require('../endpoint/iam/iam_utils');
const { generate_id } = require('../manage_nsfs/manage_nsfs_cli_utils');
const nsfs_schema_utils = require('../manage_nsfs/nsfs_schema_utils');
const IamError = require('../endpoint/iam/iam_errors').IamError;
const cloud_utils = require('../util/cloud_utils');
const SensitiveString = require('../util/sensitive_string');
const { get_symlink_config_file_path, get_config_file_path, get_config_data } = require('../manage_nsfs/manage_nsfs_cli_utils');
const nc_mkm = require('../manage_nsfs/nc_master_key_manager').get_instance();
const { account_cache } = require('./object_sdk');

const entity_enum = {
    USER: 'USER',
    ACCESS_KEY: 'ACCESS_KEY',
};

// TODO - rename (the typo), move and reuse in manage_nsfs
const acounts_dir_relative_path = '../accounts/';

////////////////////
// MOCK VARIABLES //
////////////////////
/* mock variables (until we implement the actual code), based on the example in AWS IAM API docs*/
const dummy_region = 'us-west-2';
const dummy_service_name = 's3';
const MS_PER_MINUTE = 60 * 1000;

/**
 * @implements {nb.AccountSpace}
 */
class AccountSpaceFS {
    /**
     * @param {{
     *      config_root?: string;
     *      fs_root?: string;
     *      fs_backend?: string;
     *      stats?: import('./endpoint_stats_collector').EndpointStatsCollector;
     * }} params
     */
    constructor({ config_root, fs_root, fs_backend, stats }) {
        this.config_root = config_root;
        this.accounts_dir = path.join(config_root, CONFIG_SUBDIRS.ACCOUNTS);
        this.access_keys_dir = path.join(config_root, CONFIG_SUBDIRS.ACCESS_KEYS);
        this.buckets_dir = path.join(config_root, CONFIG_SUBDIRS.BUCKETS);
        this.fs_context = native_fs_utils.get_process_fs_context();

        // Currently we do not use these properties
        this.fs_root = fs_root ?? '';
        this.fs_backend = fs_backend ?? config.NSFS_NC_CONFIG_DIR_BACKEND;
        this.stats = stats;
    }

    ////////////
    // USER   //
    ////////////

    // 1 - check that the requesting account is a root user account
    // 2 - check if username already exists
    //     GAP - it should be only under the root account in the future
    // 3 - copy the data from the root account user details to a new config file
    async create_user(params, account_sdk) {
        const action = 'create_user';
        dbg.log1(`AccountSpaceFS.${action}`, params, account_sdk);
        try {
            const requesting_account = account_sdk.requesting_account;
            this._check_if_requesting_account_is_root_account(action, requesting_account,
                { username: params.username, iam_path: params.iam_path });
            await this._check_username_already_exists(action, params.username);
            const created_account = await this._copy_data_from_requesting_account_to_account_config(action, requesting_account, params);
            return {
                iam_path: created_account.iam_path || IAM_DEFAULT_PATH,
                username: created_account.name,
                user_id: created_account._id,
                arn: create_arn(requesting_account._id, created_account.name, created_account.iam_path),
                create_date: created_account.creation_date,
            };
        } catch (err) {
            dbg.error(`AccountSpaceFS.${action} error`, err);
            throw this._translate_error_codes(err, entity_enum.USER);
        }
    }

    // 1 - check that the requesting account is a root user account
    // 2 - find the username (flag username is not required)
    // 3 - check that the user account config file exists
    // 4 - read the account config file
    // 5 - check that the user to get is not a root account
    // 6 - check that the user account to get is owned by the root account
    async get_user(params, account_sdk) {
        const action = 'get_user';
        dbg.log1(`AccountSpaceFS.${action}`, params, account_sdk);
        try {
            const requesting_account = account_sdk.requesting_account;
            const { requester } = this._check_root_account_or_user(requesting_account, params.username);
            const username = params.username ?? requester.name; // username is not required
            // GAP - we do not have the user iam_path at this point (error message)
            this._check_if_requesting_account_is_root_account(action, requesting_account,
                { username: username });
            const account_config_path = this._get_account_config_path(username);
            await this._check_if_account_config_file_exists(action, username, account_config_path);
            const account_to_get = await native_fs_utils.read_file(this.fs_context, account_config_path);
            this._check_if_requested_account_is_root_account(action, requesting_account, account_to_get, params);
            this._check_if_user_is_owned_by_root_account(action, requesting_account, account_to_get);
            return {
                user_id: account_to_get._id,
                iam_path: account_to_get.iam_path || IAM_DEFAULT_PATH,
                username: account_to_get.name,
                arn: create_arn(requesting_account._id, account_to_get.name, account_to_get.iam_path),
                create_date: account_to_get.creation_date,
                password_last_used: account_to_get.creation_date, // GAP
            };
        } catch (err) {
            dbg.error(`AccountSpaceFS.${action} error`, err);
            throw this._translate_error_codes(err, entity_enum.USER);
        }
    }

    // 1 - check that the requesting account is a root user account
    // 2 - check that the user account config file exists
    // 3 - read the account config file
    // 4 - check that the user to update is not a root account
    // 5 - check that the user account to get is owned by the root account
    // 6 - check if username was updated
    //   6.1 - check if username already exists (global scope - all config files names)
    //   6.2 - create the new config file (with the new name same data) and delete the the existing config file
    // 7 - (else not an update of username) update the config file
    // 8 - remove the access_keys from the account_cache
    async update_user(params, account_sdk) {
        const action = 'update_user';
        try {
            dbg.log1(`AccountSpaceFS.${action}`, params, account_sdk);
            const requesting_account = account_sdk.requesting_account;
            // GAP - we do not have the user iam_path at this point (error message)
            this._check_if_requesting_account_is_root_account(action, requesting_account,
                { username: params.username});
            const account_config_path = this._get_account_config_path(params.username);
            await this._check_if_account_config_file_exists(action, params.username, account_config_path);
            const account_to_update = await native_fs_utils.read_file(this.fs_context, account_config_path);
            this._check_if_requested_account_is_root_account(action, requesting_account, account_to_update, params);
            this._check_if_user_is_owned_by_root_account(action, requesting_account, account_to_update);
            const is_username_update = !_.isUndefined(params.new_username) &&
                params.new_username !== params.username;
            if (!_.isUndefined(params.new_iam_path)) account_to_update.iam_path = params.new_iam_path;
            if (is_username_update) {
                dbg.log1(`AccountSpaceFS.${action} username was updated, is_username_update`,
                    is_username_update);
                await this._update_account_config_new_username(action, params, account_to_update);
            } else {
                const account_to_update_string = JSON.stringify(account_to_update);
                nsfs_schema_utils.validate_account_schema(JSON.parse(account_to_update_string));
                await native_fs_utils.update_config_file(this.fs_context, this.accounts_dir,
                    account_config_path, account_to_update_string);
            }
            this._clean_account_cache(account_to_update);
            return {
                iam_path: account_to_update.iam_path || IAM_DEFAULT_PATH,
                username: account_to_update.name,
                user_id: account_to_update._id,
                arn: create_arn(requesting_account._id, account_to_update.name, account_to_update.iam_path),
            };
        } catch (err) {
            dbg.error(`AccountSpaceFS.${action} error`, err);
            throw this._translate_error_codes(err, entity_enum.USER);
        }
    }

    // 1 - check that the requesting account is a root user account
    // 2 - check that the user account config file exists
    // 3 - read the account config file
    // 4 - check that the deleted user is not a root account
    // 5 - check that the deleted user is owned by the root account
    // 6 - check if the user doesn’t have resources related to it (in IAM users only access keys)
    //     note: buckets are owned by the root account
    // 7 - delete the account config file
    async delete_user(params, account_sdk) {
        const action = 'delete_user';
        dbg.log1(`AccountSpaceFS.${action}`, params, account_sdk);
        try {
            const requesting_account = account_sdk.requesting_account;
            // GAP - we do not have the user iam_path at this point (error message)
            this._check_if_requesting_account_is_root_account(action, requesting_account,
                { username: params.username });
            const account_config_path = this._get_account_config_path(params.username);
            await this._check_if_account_config_file_exists(action, params.username, account_config_path);
            const account_to_delete = await native_fs_utils.read_file(this.fs_context, account_config_path);
            this._check_if_requested_account_is_root_account(action, requesting_account, account_to_delete, params);
            this._check_if_user_is_owned_by_root_account(action, requesting_account, account_to_delete);
            this._check_if_user_does_not_have_access_keys_before_deletion(action, account_to_delete);
            await native_fs_utils.delete_config_file(this.fs_context, this.accounts_dir, account_config_path);
        } catch (err) {
            dbg.error(`AccountSpaceFS.${action} error`, err);
            throw this._translate_error_codes(err, entity_enum.USER);
        }
    }

    // 1 - check that the requesting account is a root user account
    // 2 - list the config files that are owned by the root user account
    //   2.1 - if the request has path_prefix check if the user’s path starts with this path
    // 3- sort the members by username (a to z)
    async list_users(params, account_sdk) {
        const action = 'list_users';
        dbg.log1(`AccountSpaceFS.${action}`, params, account_sdk);
        try {
        const requesting_account = account_sdk.requesting_account;
        this._check_if_requesting_account_is_root_account(action, requesting_account, { });
        const is_truncated = false; // GAP - no pagination at this point
        let members = await this._list_config_files_for_users(requesting_account, params.iam_path_prefix);
        members = members.sort((a, b) => a.username.localeCompare(b.username));
        return { members, is_truncated };
        } catch (err) {
            dbg.error(`AccountSpaceFS.${action} error`, err);
            throw this._translate_error_codes(err, entity_enum.USER);
        }
    }

    ////////////////
    // ACCESS KEY //
    ////////////////

    // 1 - check that the requesting account is a root user account or that the username is same as the requester
    // 2 - check that the requested account config file exists
    // 3 - read the account config file
    // 4 - if the requester is root user account - check that it owns the account
    //     check that the access key to create is on a user is owned by the the root account
    // 5 - check that the number of access key array
    // 6 - generate access keys
    // 7 - encryption (GAP - need this functionality from nc_master_key_manager)
    // 8 - validate account
    // 9 - update account config file
    // 10 - link new access key file to config file
    async create_access_key(params, account_sdk) {
        const action = 'create_access_key';
        dbg.log1(`AccountSpaceFS.${action}`, params, account_sdk);
        try {
            const requesting_account = account_sdk.requesting_account;
            const requester = this._check_if_requesting_account_is_root_account_or_user_om_himself(action,
                requesting_account, params.username);
            const name_for_access_key = params.username ?? requester.name;
            const requested_account_config_path = this._get_account_config_path(name_for_access_key);
            await this._check_if_account_config_file_exists(action, name_for_access_key, requested_account_config_path);
            const requested_account = await native_fs_utils.read_file(this.fs_context, requested_account_config_path);
            if (requester.identity === identity_enum.ROOT_ACCOUNT) {
                this._check_if_user_is_owned_by_root_account(action, requesting_account, requested_account);
            }
            this._check_number_of_access_key_array(action, requested_account);
            const index_for_access_key = this._get_available_index_for_access_key(requested_account.access_keys);
            const { generated_access_key, generated_secret_key } = this._generate_access_key();
            // encryption GAP - need this functionality from nc_master_key_manager)
            const { encrypted_secret_key, master_key_id } = await this._encrypt_secret_key(generated_secret_key);
            requested_account.access_keys[index_for_access_key] = {
                access_key: generated_access_key,
                encrypted_secret_key: encrypted_secret_key,
                creation_date: new Date().toISOString(),
                status: access_key_status_enum.ACTIVE,
                creator_identity: requester.identity,
                master_key_id: master_key_id, // TODO - move master_key_id to account only - would lead changes in encrypt_access_keys
            };
            requested_account.master_key_id = master_key_id;
            const account_to_create_access_keys_string = JSON.stringify(requested_account);
            nsfs_schema_utils.validate_account_schema(JSON.parse(account_to_create_access_keys_string));
            await native_fs_utils.update_config_file(this.fs_context, this.accounts_dir,
                requested_account_config_path, account_to_create_access_keys_string);
            const account_config_relative_path = get_config_file_path(acounts_dir_relative_path, requested_account.name);
            const new_access_key_symlink_config_path = get_symlink_config_file_path(this.access_keys_dir, generated_access_key);
            await nb_native().fs.symlink(this.fs_context, account_config_relative_path, new_access_key_symlink_config_path);
            return {
                username: requested_account.name,
                access_key: requested_account.access_keys[index_for_access_key].access_key,
                create_date: requested_account.access_keys[index_for_access_key].creation_date,
                status: requested_account.access_keys[index_for_access_key].status,
                secret_key: generated_secret_key,
            };
        } catch (err) {
            dbg.error(`AccountSpaceFS.${action} error`, err);
            throw this._translate_error_codes(err, entity_enum.ACCESS_KEY);
        }
    }

    // 1 - read the symlink file that we get in params (access key id)
    // 2 - check if the access key that was received in param exists
    // 3 - read the config file
    // 4 - check that config file is on the same root account
    // General note: only serves the requester (no flag --user-name is passed)
    async get_access_key_last_used(params, account_sdk) {
        const action = 'get_access_key_last_used';
        dbg.log1(`AccountSpaceFS.${action}`, params, account_sdk);
        try {
            const requesting_account = account_sdk.requesting_account;
            const access_key_id = params.access_key;
            const requested_account_path = get_symlink_config_file_path(this.access_keys_dir, access_key_id);
            await this._check_if_account_exists_by_access_key_symlink(action, requesting_account, requested_account_path, access_key_id);
            const requested_account = await get_config_data(this.fs_root, requested_account_path, true);
            this._check_if_requested_account_same_as_requesting_account(action, requesting_account, requested_account, access_key_id);
            return {
                region: dummy_region, // GAP
                last_used_date: new Date(Date.now() - 30 * MS_PER_MINUTE), // GAP
                service_name: dummy_service_name, // GAP
                username: requested_account.name,
            };
        } catch (err) {
            dbg.error('AccountSpaceFS.get_access_key_last_used error', err);
            throw this._translate_error_codes(err, entity_enum.ACCESS_KEY);
        }
    }

    // 1 - check that the requesting account is a root user account or that the username is same as the requester
    // 2 - check if the access key that was received in param exists
    // 3 - read the config file
    // 4 - check that config file is on the same root account
    // 5 - check if we need to change the status (if not - return)
    // 6 - update the access key status (Active/Inactive) + decrypt and encrypt
    //     GAP - need this functionality from nc_master_key_manager
    // 7 - validate account
    // 8 - update account config file
    // 9 - remove the access_key from the account_cache
    async update_access_key(params, account_sdk) {
        const action = 'update_access_key';
        dbg.log1(`AccountSpaceFS.${action}`, params, account_sdk);
        try {
            const requesting_account = account_sdk.requesting_account;
            const access_key_id = params.access_key;
            const requester = this._check_if_requesting_account_is_root_account_or_user_om_himself(action,
                requesting_account, params.username);
            const requested_account_path = get_symlink_config_file_path(this.access_keys_dir, params.access_key);
            await this._check_if_account_exists_by_access_key_symlink(action, requesting_account, requested_account_path, access_key_id);
            const requested_account = await get_config_data(this.fs_root, requested_account_path, true);
            this._check_if_requested_account_same_as_requesting_account(action, requesting_account, requested_account, access_key_id);
            const { index_for_access_key, access_key } = this._get_access_key(requested_account, params.access_key);
            if (access_key.status === params.status) {
                dbg.log1(`AccountSpaceFS.${action} status was not change, not updating the account config file`);
                return;
            }
            // encryption GAP - need this functionality from nc_master_key_manager)
            const { secret_key } = await this._decrypt_encrypted_secret_key(access_key.encrypted_secret_key);
            const { encrypted_secret_key, master_key_id } = await this._encrypt_secret_key(secret_key);
            requested_account.access_keys[index_for_access_key].encrypted_secret_key = encrypted_secret_key;
            requested_account.access_keys[index_for_access_key].status = params.status;
            requested_account.access_keys[index_for_access_key].master_key_id = master_key_id; // temp here
            requested_account.master_key_id = master_key_id;
            const account_string = JSON.stringify(requested_account);
            nsfs_schema_utils.validate_account_schema(JSON.parse(account_string));
            const name_for_access_key = params.username ?? requester.name;
            const requested_account_config_path = this._get_account_config_path(name_for_access_key);
            await native_fs_utils.update_config_file(this.fs_context, this.accounts_dir,
                requested_account_config_path, account_string);
            this._clean_account_cache(requested_account);
        } catch (err) {
            dbg.error(`AccountSpaceFS.${action} error`, err);
            throw this._translate_error_codes(err, entity_enum.ACCESS_KEY);
        }
    }

    // 1 - check that the requesting account is a root user account or that the username is same as the requester
    // 2 - check if the access key that was received in param exists
    // 3 - read the config file
    // 4 - check that config file is on the same root account
    // 5 - delete the access key object (access key, secret key, status, etc.) from the array
    // 6 - encryption (secret key) - only because we want the most updated master_key id
    //     GAP - after moving to master_key_id only in account level
    // 7 - validate account
    // 8 - update account config file
    // 9 -  unlink the symbolic link
    // 10 - remove the access_key from the account_cache
    async delete_access_key(params, account_sdk) {
        const action = 'delete_access_key';
        dbg.log1(`AccountSpaceFS.${action}`, params, account_sdk);
        try {
            const requesting_account = account_sdk.requesting_account;
            const access_key_id = params.access_key;
            const requester = this._check_if_requesting_account_is_root_account_or_user_om_himself(action,
                requesting_account, params.username);
            const requested_account_path = get_symlink_config_file_path(this.access_keys_dir, access_key_id);
            await this._check_if_account_exists_by_access_key_symlink(action, requesting_account, requested_account_path, access_key_id);
            const requested_account = await get_config_data(this.fs_root, requested_account_path, true);
            this._check_if_requested_account_same_as_requesting_account(action, requesting_account, requested_account, access_key_id);
            const { index_for_access_key } = this._get_access_key(requested_account, access_key_id);
            requested_account.access_keys.splice(index_for_access_key, 1);
            // 6 - encryption (secret key) - only because we want the most updated master_key id
            //     GAP - after moving to master_key_id only in account level
            const account_string = JSON.stringify(requested_account);
            nsfs_schema_utils.validate_account_schema(JSON.parse(account_string));
            const name_for_access_key = params.username ?? requester.name;
            const account_config_path = this._get_account_config_path(name_for_access_key);
            await native_fs_utils.update_config_file(this.fs_context, this.accounts_dir,
                account_config_path, account_string);
            await nb_native().fs.unlink(this.fs_context, requested_account_path);
            this._clean_account_cache(requested_account);
        } catch (err) {
            dbg.error(`AccountSpaceFS.${action} error`, err);
            throw this._translate_error_codes(err, entity_enum.ACCESS_KEY);
        }
    }

    // 1 - check that the requesting account is a root user account or that the username is same as the requester
    // 2 - check that the user account config file exists
    // 3 - read the account config file
    // 4 - check that config file is on the same root account
    // 5 - list the access-keys
    // 6 - members should be sorted by access_key (a to z)
    //     GAP - this is not written in the docs, only inferred (maybe it sorted is by create_date?)
    async list_access_keys(params, account_sdk) {
        const action = 'list_access_keys';
        dbg.log1(`AccountSpaceFS.${action}`, params, account_sdk);
        try {
            const requesting_account = account_sdk.requesting_account;
            const access_key_id = params.access_key;
            const requester = this._check_if_requesting_account_is_root_account_or_user_om_himself(action,
                requesting_account, params.username);
            const name_for_access_key = params.username ?? requester.name;
            const requested_account_config_path = this._get_account_config_path(name_for_access_key);
            await this._check_if_account_config_file_exists(action, name_for_access_key, requested_account_config_path);
            const requested_account = await native_fs_utils.read_file(this.fs_context, requested_account_config_path);
            this._check_if_requested_account_same_as_requesting_account(action, requesting_account, requested_account, access_key_id);
            const is_truncated = false; // path_prefix is not supported
            let members = this._list_access_keys_from_account(requested_account);
            members = members.sort((a, b) => a.access_key.localeCompare(b.access_key));
            return { members, is_truncated, username: name_for_access_key };
        } catch (err) {
            dbg.error(`AccountSpaceFS.${action} error`, err);
            throw this._translate_error_codes(err, entity_enum.ACCESS_KEY);
        }
    }

    ////////////////////////
    // INTERNAL FUNCTIONS //
    ////////////////////////

     _get_account_config_path(name) {
         return path.join(this.accounts_dir, name + '.json');
     }

     _get_access_keys_config_path(access_key) {
         return path.join(this.access_keys_dir, access_key + '.symlink');
     }

     _new_user_defaults(requesting_account, params) {
        const distinguished_name = requesting_account.nsfs_account_config.distinguished_name;
        return {
            _id: generate_id(),
            name: params.username,
            email: params.username,
            creation_date: new Date().toISOString(),
            owner: requesting_account._id,
            creator: requesting_account._id,
            iam_path: params.iam_path || IAM_DEFAULT_PATH,
            master_key_id: requesting_account.master_key_id, // doesn't have meaning when user has just created (without access keys), TODO: tke from current master key manage and not just copy from the root account
            allow_bucket_creation: requesting_account.allow_bucket_creation,
            force_md5_etag: requesting_account.force_md5_etag,
            access_keys: [],
            nsfs_account_config: {
                distinguished_name: distinguished_name,
                uid: distinguished_name ? undefined : requesting_account.nsfs_account_config.uid,
                gid: distinguished_name ? undefined : requesting_account.nsfs_account_config.gid,
                new_buckets_path: requesting_account.nsfs_account_config.new_buckets_path,
                fs_backend: requesting_account.nsfs_account_config.fs_backend,
            }
        };
    }

    // this function was copied from namespace_fs and bucketspace_fs
    // It is a fallback that we use, but might be not accurate
    _translate_error_codes(err, entity) {
        if (err.rpc_code) return err;
        if (err.code === 'ENOENT') err.rpc_code = `NO_SUCH_${entity}`;
        if (err.code === 'EEXIST') err.rpc_code = `${entity}_ALREADY_EXISTS`;
        if (err.code === 'EPERM' || err.code === 'EACCES') err.rpc_code = 'UNAUTHORIZED';
        if (err.code === 'IO_STREAM_ITEM_TIMEOUT') err.rpc_code = 'IO_STREAM_ITEM_TIMEOUT';
        if (err.code === 'INTERNAL_ERROR') err.rpc_code = 'INTERNAL_ERROR';
        return err;
    }

    _check_root_account(account) {
        if (_.isUndefined(account.owner) ||
            account.owner === account._id) {
            return true;
        }
        return false;
    }

    _check_root_account_owns_user(root_account, user_account) {
        if (_.isUndefined(user_account.owner)) return false;
        return root_account._id === user_account.owner;
    }

    _throw_access_denied_error(action, requesting_account, details = {}, entity = entity_enum.USER) {
        const full_action_name = get_action_message_title(action);
        const arn_for_requesting_account = create_arn(requesting_account._id,
            requesting_account.name.unwrap(), requesting_account.path);
        const basic_message = `User: ${arn_for_requesting_account} is not authorized to perform:` +
        `${full_action_name} on resource: `;
        let message_with_details;
        if (entity === entity_enum.USER) {
            let user_message;
            if (action === 'list_access_keys') {
                user_message = `user ${requesting_account.name.unwrap()}`;
            } else {
                user_message = create_arn(requesting_account._id, details.username, details.path);
            }
            message_with_details = basic_message +
            `${user_message} because no identity-based policy allows the ${full_action_name} action`;
        } else { // entity_enum.ACCESS_KEY
            message_with_details = basic_message + `access key ${details.access_key}`;
        }
        const { code, http_code, type } = IamError.AccessDenied;
        throw new IamError({ code, message: message_with_details, http_code, type });
    }

    // based on the function from manage_nsfs
    async _list_config_files_for_users(requesting_account, iam_path_prefix) {
        const entries = await nb_native().fs.readdir(this.fs_context, this.accounts_dir);
        const should_filter_by_prefix = check_iam_path_was_set(iam_path_prefix);

        const config_files_list = await P.map_with_concurrency(10, entries, async entry => {
            if (entry.name.endsWith('.json')) {
                const full_path = path.join(this.accounts_dir, entry.name);
                const account_data = await native_fs_utils.read_file(this.fs_context, full_path);
                if (entry.name.includes(config.NSFS_TEMP_CONF_DIR_NAME)) return undefined;
                if (this._check_root_account_owns_user(requesting_account, account_data)) {
                    if (should_filter_by_prefix) {
                        if (_.isUndefined(account_data.iam_path)) return undefined;
                        if (!account_data.iam_path.startsWith(iam_path_prefix)) return undefined;
                    }
                    const user_data = {
                        user_id: account_data._id,
                        iam_path: account_data.iam_path || IAM_DEFAULT_PATH,
                        username: account_data.name,
                        arn: create_arn(requesting_account._id, account_data.name, account_data.iam_path),
                        create_date: account_data.creation_date,
                        password_last_used: Date.now(), // GAP
                    };
                    return user_data;
                }
                return undefined;
            }
        });
        // remove undefined entries
        return config_files_list.filter(item => item);
    }

    _check_if_requesting_account_is_root_account(action, requesting_account, user_details = {}) {
        const is_root_account = this._check_root_account(requesting_account);
        dbg.log1(`AccountSpaceFS.${action} requesting_account`, requesting_account,
            'is_root_account', is_root_account);
        if (!is_root_account) {
            dbg.error(`AccountSpaceFS.${action} requesting account is not a root account`,
                requesting_account);
            this._throw_access_denied_error(action, requesting_account, user_details);
        }
    }

    _check_if_requested_account_is_root_account(action, requesting_account, requested_account, user_details = {}) {
        const is_requested_account_root_account = this._check_root_account(requested_account);
        dbg.log1(`AccountSpaceFS.${action} requested_account`, requested_account,
            'is_requested_account_root_account', is_requested_account_root_account);
        if (is_requested_account_root_account) {
            dbg.error(`AccountSpaceFS.${action} requested account is a root account`,
            requested_account);
            this._throw_access_denied_error(action, requesting_account, user_details);
        }
    }

    async _check_username_already_exists(action, username) {
            const account_config_path = this._get_account_config_path(username);
            const name_exists = await native_fs_utils.is_path_exists(this.fs_context,
                account_config_path);
            if (name_exists) {
                dbg.error(`AccountSpaceFS.${action} username already exists`, username);
                const message_with_details = `User with name ${username} already exists.`;
                const { code, http_code, type } = IamError.EntityAlreadyExists;
                throw new IamError({ code, message: message_with_details, http_code, type });
            }
    }

    async _copy_data_from_requesting_account_to_account_config(action, requesting_account, params) {
        const created_account = this._new_user_defaults(requesting_account, params);
        dbg.log1(`AccountSpaceFS.${action} new_account`, created_account);
        const new_account_string = JSON.stringify(created_account);
        nsfs_schema_utils.validate_account_schema(JSON.parse(new_account_string));
        const account_config_path = this._get_account_config_path(params.username);
        await native_fs_utils.create_config_file(this.fs_context, this.accounts_dir,
            account_config_path, new_account_string);
        return created_account;
    }

    async _check_if_account_config_file_exists(action, username, account_config_path) {
        const is_user_account_exists = await native_fs_utils.is_path_exists(this.fs_context,
            account_config_path);
        if (!is_user_account_exists) {
            dbg.error(`AccountSpaceFS.${action} username does not exist`, username);
            const message_with_details = `The user with name ${username} cannot be found.`;
            const { code, http_code, type } = IamError.NoSuchEntity;
            throw new IamError({ code, message: message_with_details, http_code, type });
        }
    }

    _check_if_user_is_owned_by_root_account(action, requesting_account, requested_account) {
        const is_user_account_to_get_owned_by_root_user = this._check_root_account_owns_user(requesting_account, requested_account);
        if (!is_user_account_to_get_owned_by_root_user) {
            dbg.error(`AccountSpaceFS.${action} requested account is not owned by root account`,
                requested_account);
            const message_with_details = `The user with name ${requested_account.name} cannot be found.`;
            const { code, http_code, type } = IamError.NoSuchEntity;
            throw new IamError({ code, message: message_with_details, http_code, type });
        }
    }

    _check_if_user_does_not_have_access_keys_before_deletion(action, account_to_delete) {
        const is_access_keys_removed = account_to_delete.access_keys.length === 0;
        if (!is_access_keys_removed) {
            dbg.error(`AccountSpaceFS.${action} requested account has access keys`,
                account_to_delete);
            const message_with_details = `Cannot delete entity, must delete access keys first.`;
            const { code, http_code, type } = IamError.DeleteConflict;
            throw new IamError({ code, message: message_with_details, http_code, type });
        }
    }

    async _update_account_config_new_username(action, params, account_to_update) {
        await this._check_username_already_exists(action, params.new_username);
        account_to_update.name = params.new_username;
        account_to_update.email = params.new_username; // internally saved
        const account_to_update_string = JSON.stringify(account_to_update);
        nsfs_schema_utils.validate_account_schema(JSON.parse(account_to_update_string));
        const new_username_account_config_path = this._get_account_config_path(params.new_username);
        await native_fs_utils.create_config_file(this.fs_context, this.accounts_dir,
            new_username_account_config_path, account_to_update_string);
        const account_config_path = this._get_account_config_path(params.username);
        await native_fs_utils.delete_config_file(this.fs_context, this.accounts_dir,
            account_config_path);
    }

    _check_root_account_or_user(requesting_account, username) {
        let is_root_account_or_user_on_itself = false;
        let requester = {};
        const requesting_account_name = requesting_account.name instanceof SensitiveString ?
            requesting_account.name.unwrap() : requesting_account.name;
        // root account (on user or himself)
        if (this._check_root_account(requesting_account)) {
            requester = {
                name: requesting_account_name,
                identity: identity_enum.ROOT_ACCOUNT
            };
            is_root_account_or_user_on_itself = true;
            return { is_root_account_or_user_on_itself, requester};
        }
        // user (on himself) - username can be undefined
        if (_.isUndefined(username) || requesting_account_name === username) {
            const username_to_use = username ?? requesting_account_name;
            requester = {
                name: username_to_use,
                identity: identity_enum.USER
            };
            is_root_account_or_user_on_itself = true;
            return { is_root_account_or_user_on_itself, requester };
        }
        return { is_root_account_or_user_on_itself, requester };
    }

    // TODO reuse set_access_keys from manage_nsfs
    _generate_access_key() {
        let generated_access_key;
        let generated_secret_key;
        ({ access_key: generated_access_key, secret_key: generated_secret_key } = cloud_utils.generate_access_keys());
        generated_access_key = generated_access_key.unwrap();
        generated_secret_key = generated_secret_key.unwrap();
        return { generated_access_key, generated_secret_key};
    }

    _get_available_index_for_access_key(access_keys) {
        // empty array or array with 1 access keys in index 1
        if (access_keys.length === 0 || _.isUndefined(access_keys[0])) {
            return 0;
        }
        return 1;
    }

    // TODO move and reuse from nc_mkm
    async _encrypt_secret_key(secret_key) {
        await nc_mkm.init();
        const master_key_id = nc_mkm.active_master_key.id;
        const encrypted_secret_key = await nc_mkm.encrypt(secret_key, master_key_id);
        return { encrypted_secret_key, master_key_id };
    }

    // TODO move and reuse from nc_mkm
    async _decrypt_encrypted_secret_key(encrypted_secret_key) {
        await nc_mkm.init();
        const master_key_id = nc_mkm.active_master_key.id;
        const secret_key = await nc_mkm.decrypt(encrypted_secret_key, master_key_id);
        return { secret_key, master_key_id };
    }

    _check_specific_access_key_exists(access_keys, access_key_to_find) {
        for (const access_key of access_keys) {
            if (access_key_to_find === access_key) {
                return true;
            }
        }
        return false;
    }

    _get_access_key(account_config, access_key_to_find) {
        const index = _.findIndex(account_config.access_keys, item => item.access_key === access_key_to_find);
        return {
            access_key: account_config.access_keys[index],
            index_for_access_key: index,
        };
    }

    _list_access_keys_from_account(account) {
        const members = [];
        for (const access_key of account.access_keys) {
            const member = {
                username: account.name,
                access_key: access_key.access_key,
                status: access_key.status ?? access_key_status_enum.ACTIVE,
                create_date: access_key.creation_date ?? account.creation_date,
            };
            members.push(member);
        }
        return members;
    }

    _check_if_requesting_account_is_root_account_or_user_om_himself(action, requesting_account, username) {
        const { is_root_account_or_user_on_itself, requester } = this._check_root_account_or_user(
            requesting_account,
            username
        );
        dbg.log1(`AccountSpaceFS.${action} requesting_account`, requesting_account,
        'is_root_account_or_user_on_itself', is_root_account_or_user_on_itself);
        if (!is_root_account_or_user_on_itself) {
            dbg.error(`AccountSpaceFS.${action} requesting account is neither a root account ` +
            `nor user requester on himself`,
            requesting_account);
            this._throw_access_denied_error(action, requesting_account, { username });
        }
        return requester;
    }

    _check_number_of_access_key_array(action, requested_account) {
        if (requested_account.access_keys.length >= MAX_NUMBER_OF_ACCESS_KEYS) {
            dbg.error(`AccountSpaceFS.${action} requested account is not owned by root account `,
            requested_account);
            const message_with_details = `Cannot exceed quota for AccessKeysPerUser: ${MAX_NUMBER_OF_ACCESS_KEYS}.`;
            const { code, http_code, type } = IamError.LimitExceeded;
            throw new IamError({ code, message: message_with_details, http_code, type });
        }
    }

    async _check_if_account_exists_by_access_key_symlink(action, requesting_account, account_path, access_key) {
        const is_user_account_exists = await native_fs_utils.is_path_exists(this.fs_context, account_path);
        if (!is_user_account_exists) {
            this._throw_access_denied_error(action, requesting_account, { access_key: access_key }, entity_enum.ACCESS_KEY);
        }
    }

    _check_if_requested_account_same_as_requesting_account(action, requesting_account, requested_account, access_key) {
        // 4 - check that config file is on the same root account
        const root_account_id_requesting_account = requesting_account.owner || requesting_account._id; // if it is root account then there is no owner
        const root_account_id_config_data = requested_account.owner || requested_account._id;
        if (root_account_id_requesting_account !== root_account_id_config_data) {
            this._throw_access_denied_error(action, requesting_account, { access_key }, entity_enum.ACCESS_KEY);
        }
    }

    // we will se it after changes in the account (user or access keys)
    _clean_account_cache(requested_account) {
        for (const access_keys of requested_account.access_keys) {
            const access_key_id = access_keys.access_key;
            account_cache.invalidate(access_key_id);
        }
    }
}

// EXPORTS
module.exports = AccountSpaceFS;
