/* Copyright (C) 2016 NooBaa */
'use strict';

module.exports = {
    $id: 'account_schema',
    type: 'object',
    required: [
        '_id',
        'name',
        'email', // temp, keep the email internally
        'access_keys',
        'nsfs_account_config',
        'creation_date',
        'allow_bucket_creation',
        'master_key_id',
    ],
    properties: {
        _id: {
            type: 'string',
        },
        name: {
            type: 'string'
        },
        email: {
            type: 'string',
        },
        creation_date: {
            type: 'string',
        },
        // owner is the account id that owns this account (permission wise)
        owner: {
            type: 'string'
        },
        // creator is the account id that created this account (internal information)
        creator: {
            type: 'string',
        },
        // AWS IAM path (identifier)
        iam_path: {
            type: 'string'
        },
        master_key_id: {
            objectid: true
        },
        allow_bucket_creation: {
            type: 'boolean',
        },
        force_md5_etag: {
            type: 'boolean',
        },
        access_keys: {
            type: 'array',
            items: {
                type: 'object',
                required: ['access_key', 'encrypted_secret_key'],
                properties: {
                    access_key: {
                        type: 'string',
                    },
                    encrypted_secret_key: {
                        type: 'string',
                    },
                    creation_date: {
                        type: 'string',
                    },
                    // we would need to translate the is_active to 'Active' and 'Inactive' strings
                    is_active: {
                        type: 'boolean',
                    },
                    // temp - put here for multiple access keys (need to discuss)
                    master_key_id: {
                        objectid: true
                    }
                }
            }
        },
        nsfs_account_config: {
            oneOf: [{
                type: 'object',
                required: ['uid', 'gid'],
                properties: {
                    uid: { type: 'number' },
                    gid: { type: 'number' },
                    new_buckets_path: { type: 'string' },
                    fs_backend: {
                        $ref: 'common_api#/definitions/fs_backend'
                    }
                }
            }, {
                type: 'object',
                required: [ 'distinguished_name'],
                properties: {
                    distinguished_name: { type: 'string' },
                    new_buckets_path: { type: 'string' },
                    fs_backend: {
                        $ref: 'common_api#/definitions/fs_backend'
                    }
                }
            }]
        },
    }
};
