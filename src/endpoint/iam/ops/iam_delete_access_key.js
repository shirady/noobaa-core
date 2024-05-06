/* Copyright (C) 2024 NooBaa */
'use strict';

const dbg = require('../../../util/debug_module')(__filename);

/**
 * https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeleteAccessKey.html
 */
async function delete_access_key(req, res) {

    const params = {
        user_name: req.body.user_name,
        access_key: req.body.access_key_id
    };
    dbg.log1('IAM DELETE ACCESS KEY', params);
    await req.account_sdk.delete_access_key(params, req.account_sdk);

    return {
        DeleteAccessKeyResponse: {
            ResponseMetadata: {
                RequestId: req.request_id,
            }
        }
    };
}

module.exports = {
    handler: delete_access_key,
    body: {
        type: 'xml',
    },
    reply: {
        type: 'xml',
    },
};
