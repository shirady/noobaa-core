/* Copyright (C) 2024 NooBaa */
'use strict';

const dbg = require('../../../util/debug_module')(__filename);

/**
 * https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateAccessKey.html
 */
async function update_access_key(req, res) {

    const params = {
        access_key: req.body.access_key_id,
        status: req.body.status,
        user_name: req.body.user_name,
    };
    dbg.log1('IAM UPDATE ACCESS KEY', params);
    await req.account_sdk.update_access_key(params);

    return {
        UpdateAccessKeyResponse: {
            ResponseMetadata: {
                RequestId: req.request_id,
            }
        }
    };
}

module.exports = {
    handler: update_access_key,
    body: {
        type: 'xml',
    },
    reply: {
        type: 'xml',
    },
};
