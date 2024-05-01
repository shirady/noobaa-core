/* Copyright (C) 2024 NooBaa */
'use strict';

const dbg = require('../../../util/debug_module')(__filename);

/**
 * https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeleteUser.html
 */
async function delete_user(req, res) {


    const params = {
        username: req.body.user_name,
    };
    dbg.log1('IAM DELETE USER', params);
    await req.account_sdk.delete_user(params);

    return {
        DeleteUserResponse: {
            ResponseMetadata: {
                RequestId: req.request_id,
            }
        }
    };
}

module.exports = {
    handler: delete_user,
    body: {
        type: 'xml',
    },
    reply: {
        type: 'xml',
    },
};
