/* Copyright (C) 2024 NooBaa */
'use strict';

const _ = require('lodash');
const path = require('path');
const config = require('../../config');
const dbg = require('../util/debug_module')(__filename);
const nb_native = require('../util/nb_native');
const native_fs_utils = require('../util/native_fs_utils');
const { CONFIG_SUBDIRS } = require('../manage_nsfs/manage_nsfs_constants');
const { create_arn, AWS_EMPTY_PATH, get_gull_action_name } = require('../endpoint/iam/iam_utils');
const { generate_id } = require('../manage_nsfs/manage_nsfs_cli_utils');
const nsfs_schema_utils = require('../manage_nsfs/nsfs_schema_utils');
const IamError = require('../endpoint/iam/iam_errors').IamError;

const access_key_status_enum = {
    ACTIVE: 'ACTIVE',
    INACTIVE: 'INACTIVE',
};

////////////////////
// MOCK VARIABLES //
////////////////////
/* mock variables (until we implement the actual code), based on the example in AWS IAM API docs*/

// account_id should be taken from the root user (account._id in the config file);
const dummy_account_id = '12345678012'; // for the example
// user_id should be taken from config file of the new created user user (account._id in the config file);
const dummy_user_id = '12345678013'; // for the example
// user should be from the the config file and the details (this for the example)
const dummy_path = '/division_abc/subdivision_xyz/';
const dummy_username1 = 'Bob';
const dummy_username2 = 'Robert';
const dummy_username_requester = 'Alice';
const dummy_user1 = {
    username: dummy_username1,
    user_id: dummy_user_id,
    path: dummy_path,
};
const dummy_user2 = {
    username: dummy_username2,
    user_id: dummy_user_id + 4,
    path: dummy_path,
};
// the requester at current implementation is the root user (this is for the example)
const dummy_requester = {
    username: dummy_username_requester,
    user_id: dummy_account_id,
    path: AWS_EMPTY_PATH,
};
const MS_PER_MINUTE = 60 * 1000;
const dummy_access_key1 = {
    username: dummy_username1,
    access_key: 'AKIAIOSFODNN7EXAMPLE',
    status: access_key_status_enum.ACTIVE,
    secret_key: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLE',
};
const dummy_access_key2 = {
    username: dummy_username2,
    access_key: 'CMCTDRBIDNN9EXAMPLE',
    status: access_key_status_enum.ACTIVE,
    secret_key: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLE',
};
const dummy_requester_access_key = {
    username: dummy_username_requester,
    access_key: 'BLYDNFMRUCIS8EXAMPLE',
    status: access_key_status_enum.ACTIVE,
    secret_key: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLE',
};
const dummy_region = 'us-west-2';
const dummy_service_name = 's3';

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
    constructor({config_root, fs_root, fs_backend, stats}) {
        this.config_root = config_root;
        this.fs_root = _.isUndefined(fs_root) ? '' : fs_root;
        this.fs_backend = fs_backend;
        this.stats = stats;

        this.accounts_dir = path.join(config_root, CONFIG_SUBDIRS.ACCOUNTS);
        this.access_keys_dir = path.join(config_root, CONFIG_SUBDIRS.ACCESS_KEYS);
        this.bucket_schema_dir = path.join(config_root, CONFIG_SUBDIRS.BUCKETS);
        this.config_root = config_root;
        this.fs_context = {
            uid: process.getuid(),
            gid: process.getgid(),
            warn_threshold_ms: config.NSFS_WARN_THRESHOLD_MS,
            fs_backend: config.NSFS_NC_CONFIG_DIR_BACKEND
            //fs_context.report_fs_stats = this.stats.update_fs_stats;
        };
    }

    ////////////
    // USER   //
    ////////////

    async create_user(params, account_sdk) {
        dbg.log1('AccountSpaceFS.create_user', params, account_sdk);
        // 1 - check that the requesting account is a root user account
        const requesting_account = account_sdk.requesting_account;
        const is_root_account = this._check_root_account(requesting_account);
        dbg.log0('AccountSpaceFS.create_user requesting_account', requesting_account,
            'is_root_account', is_root_account);
        if (!is_root_account) {
            dbg.error('AccountSpaceFS.create_user requesting account is not a root account',
                requesting_account);
                const detail = `User is not authorized to perform ${get_gull_action_name('create_user')}`;
                const { code, message, http_code } = IamError.NotAuthorized;
                throw new IamError({ code, message, http_code, detail });
        }
        // 2 - check if username already exists (global scope - all config files names)
        // GAP - it should be only under the root account in the future
        const account_config_path = this._get_account_config_path(params.username);
        const name_exists = await native_fs_utils.is_path_exists(this.fs_context, account_config_path);
        if (name_exists) {
            dbg.error('AccountSpaceFS.create_user username already exists', params.username);
            const detail = `User with name ${params.username} already exists.`;
            const { code, message, http_code } = IamError.EntityAlreadyExists;
            throw new IamError({ code, message, http_code, detail });
        }
        // 3 - copy the data from the root account user details to a new config file
        const new_account = this._new_user_defaults(requesting_account, params);
        dbg.log0('AccountSpaceFS.create_user new_account', new_account);
        try {
            const new_account_string = JSON.stringify(new_account);
            nsfs_schema_utils.validate_account_schema(JSON.parse(new_account_string));
            await native_fs_utils.create_config_file(this.fs_context, this.accounts_dir, account_config_path, new_account_string);
            return {
                path: new_account.path,
                username: new_account.name,
                user_id: new_account._id,
                arn: create_arn(requesting_account._id, new_account.name, new_account.path),
                create_date: new_account.creation_date,
            };
        } catch (err) {
            throw this._translate_error_codes(err);
        }
    }

    async get_user(params, account_sdk) {
        dbg.log1('AccountSpaceFS.get_user', params, account_sdk);
        // 1 - check that the requesting account is a root user account
        const requesting_account = account_sdk.requesting_account;
        const is_root_account = this._check_root_account(requesting_account);
        dbg.log0('AccountSpaceFS.get_user requesting_account', requesting_account,
            'is_root_account', is_root_account);
        if (!is_root_account) {
            dbg.error('AccountSpaceFS.get_user requesting account is not a root account',
                requesting_account);
                const detail = `User is not authorized to perform ${get_gull_action_name('get_user')}`;
                const { code, message, http_code } = IamError.NotAuthorized;
                throw new IamError({ code, message, http_code, detail });
        }
        // 2 - check that the user account config file exists
        const account_config_path = this._get_account_config_path(params.username);
        const is_user_account_exists = await native_fs_utils.is_path_exists(this.fs_context, account_config_path);
        if (!is_user_account_exists) {
            dbg.error('AccountSpaceFS.get_user username does not exist', params.username);
            const detail = `The user with name ${params.username} cannot be found.`;
            const { code, message, http_code } = IamError.NoSuchEntity;
            throw new IamError({ code, message, http_code, detail });
        }
        // 3 - read the account config file
        let account_to_get;
        try {
            account_to_get = await native_fs_utils.read_file(this.fs_context, account_config_path);
        } catch (err) {
            throw this._translate_error_codes(err);
        }
        // 4 - check that the user account to get is owned by the root account
        const is_user_account_to_get_owned_by_root_user = this._check_root_account_owns_user(requesting_account, account_to_get);
        if (!is_user_account_to_get_owned_by_root_user) {
            dbg.error('AccountSpaceFS.get_user requested account is not owned by root account',
            account_to_get);
            const detail = `User is not authorized to perform ${get_gull_action_name('get_user')}`;
            const { code, message, http_code } = IamError.NotAuthorized;
            throw new IamError({ code, message, http_code, detail });
        }
        // 5 - send the details
        return {
            user_id: account_to_get._id,
            path: account_to_get.path,
            username: account_to_get.name,
            arn: create_arn(requesting_account._id, account_to_get.name, account_to_get.path),
            create_date: account_to_get.creation_date,
            password_last_used: account_to_get.creation_date, // GAP
        };
    }

    async update_user(params, account_sdk) {
        dbg.log1('update_user', params);
        const path_friendly = params.new_path ? params.new_path : dummy_user1.path;
        const username = params.new_username ? params.new_username : params.username;
        return {
            path: path_friendly,
            username: username,
            user_id: dummy_user1.user_id,
            arn: create_arn(dummy_account_id, username, path_friendly),
        };
    }

    async delete_user(params, account_sdk) {
        dbg.log1('AccountSpaceFS.delete_user', params, account_sdk);
        // 1 - check that the requesting account is a root user account
        const requesting_account = account_sdk.requesting_account;
        const is_root_account = this._check_root_account(requesting_account);
        dbg.log0('AccountSpaceFS.delete_user requesting_account', requesting_account,
            'is_root_account', is_root_account);
        if (!is_root_account) {
            dbg.error('AccountSpaceFS.delete_user requesting account is not a root account',
                requesting_account);
                const detail = `User is not authorized to perform ${get_gull_action_name('delete_user')}`;
                const { code, message, http_code } = IamError.NotAuthorized;
                throw new IamError({ code, message, http_code, detail });
        }
        // 2 - check that the deleted account config file exists
        const account_config_path = this._get_account_config_path(params.username);
        const is_deleted_account_exists = await native_fs_utils.is_path_exists(this.fs_context, account_config_path);
        if (!is_deleted_account_exists) {
            dbg.error('AccountSpaceFS.delete_user username does not exist', params.username);
            const detail = `The user with name ${params.username} cannot be found.`;
            const { code, message, http_code } = IamError.NoSuchEntity;
            throw new IamError({ code, message, http_code, detail });
        }
        // 3 - read the account config file
        let account_to_delete;
        try {
            account_to_delete = await native_fs_utils.read_file(this.fs_context, account_config_path);
        } catch (err) {
            throw this._translate_error_codes(err);
        }
        // 4 - check that the deleted user is not a root account
        const is_deleted_account_root_account = this._check_root_account(account_to_delete);
        dbg.log0('AccountSpaceFS.delete_user account_to_delete', account_to_delete,
            'is_deleted_account_root_account', is_deleted_account_root_account);
        if (is_deleted_account_root_account) {
            dbg.error('AccountSpaceFS.delete_user requested account is a root account',
            account_to_delete);
            const detail = `User is not authorized to perform ${get_gull_action_name('delete_user')}`;
            const { code, message, http_code } = IamError.NotAuthorized;
            throw new IamError({ code, message, http_code, detail });
        }
        // 5 - check that the deleted user is owned by the root account
        const is_deleted_account_owned_by_root_user = this._check_root_account_owns_user(requesting_account, account_to_delete);
        if (!is_deleted_account_owned_by_root_user) {
            dbg.error('AccountSpaceFS.delete_user requested account is not owned by root account',
            account_to_delete);
            const detail = `User is not authorized to perform ${get_gull_action_name('delete_user')}`;
            const { code, message, http_code } = IamError.NotAuthorized;
            throw new IamError({ code, message, http_code, detail });
        }
        // 6 - check if the user doesn’t have items related to it (in our case only access keys)
        const is_access_keys_removed = account_to_delete.access_keys.length === 0;
        if (!is_access_keys_removed) {
            dbg.error('AccountSpaceFS.delete_user requested account has access keys',
            account_to_delete);
            const detail = `Cannot delete entity, must delete access keys first.`;
            const { code, message, http_code } = IamError.DeleteConflict;
            throw new IamError({ code, message, http_code, detail });
        }
        // 7 - delete the account
        try {
            await native_fs_utils.delete_config_file(this.fs_context, this.accounts_dir, account_config_path);
        } catch (err) {
            throw this._translate_error_codes(err);
        }
    }

    async list_users(params, account_sdk) {
        dbg.log1('list_users', params);
        const is_truncated = false;
        // path_prefix is not supported in the example
        const members = [
            {
                user_id: dummy_user1.user_id,
                path: dummy_user1.path,
                username: dummy_user1.username,
                arn: create_arn(dummy_account_id, dummy_user1.username, dummy_user1.path),
                create_date: new Date(Date.now() - 30 * MS_PER_MINUTE),
                password_last_used: new Date(Date.now() - MS_PER_MINUTE),
            },
            {
                user_id: dummy_user2.user_id,
                path: dummy_user2.path,
                username: dummy_user2.username,
                arn: create_arn(dummy_account_id, dummy_user2.username, dummy_user1.path),
                create_date: new Date(Date.now() - 30 * MS_PER_MINUTE),
                password_last_used: new Date(Date.now() - MS_PER_MINUTE),
            }
        ];
        // members should be sorted by username (a to z)
        return { members, is_truncated };
    }

    ////////////////
    // ACCESS KEY //
    ////////////////

    async create_access_key(params, account_sdk) {
        const { dummy_access_key } = get_user_details(params.username);
        dbg.log1('create_access_key', params);
        return {
            username: dummy_access_key.username,
            access_key: dummy_access_key.access_key,
            status: dummy_access_key.status,
            secret_key: dummy_access_key.secret_key,
        };
    }

    async update_access_key(params, account_sdk) {
        dbg.log1('update_access_key', params);
        // nothing to do at this point
    }

    async get_access_key_last_used(params, account_sdk) {
        dbg.log1('get_access_key_last_used', params);
        return {
            region: dummy_region,
            last_used_date: new Date(Date.now() - 30 * MS_PER_MINUTE),
            service_name: dummy_service_name,
            username: dummy_user1.username,
        };
    }

    async delete_access_key(params, account_sdk) {
        dbg.log1('delete_access_key', params);
        // nothing to do at this point
    }

    async list_access_keys(params, account_sdk) {
        dbg.log1('list_access_keys', params);
        const is_truncated = false;
        const { dummy_user } = get_user_details(params.username);
        const username = dummy_user.username;
        // path_prefix is not supported in the example
        const members = [
            {
                username: dummy_access_key1.username,
                access_key: dummy_access_key1.access_key,
                status: dummy_access_key1.status,
                create_date: new Date(Date.now() - 30 * MS_PER_MINUTE),
            },
            {
                username: dummy_access_key2.username,
                access_key: dummy_access_key2.access_key,
                status: dummy_access_key2.status,
                create_date: new Date(Date.now() - 30 * MS_PER_MINUTE),
            },
        ];
        return { members, is_truncated, username};
    }

    ////////////////////////
    // INTERNAL FUNCTIONS //
    ////////////////////////
    /* currently based or copied from bucketspace_fs */

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
            path: params.path,
            master_key_id: requesting_account.master_key_id, // it is per system, we can copy from the account
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
}

//////////////////////
// HELPER FUNCTIONS //
//////////////////////

/**
 * get_user_details will return the relevant details of the user since username is not required in some requests
 * (If it is not included, it defaults to the user making the request).
 * If the username is passed in the request than it is this user
 * else (undefined) is is the requester
 * @param {string} username
 */
function get_user_details(username) {
    const res = {
        dummy_user: dummy_requester,
        dummy_access_key: dummy_requester_access_key,
    };
    const is_user_request = Boolean(username); // can be user request or root user request
    if (is_user_request) {
        res.dummy_user = dummy_user1;
        res.dummy_access_key = dummy_access_key1;
    }
    return res;
}

// EXPORTS
module.exports = AccountSpaceFS;
