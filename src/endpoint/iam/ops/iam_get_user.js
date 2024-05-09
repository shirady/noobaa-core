/* Copyright (C) 2024 NooBaa */
'use strict';

const dbg = require('../../../util/debug_module')(__filename);
const iam_utils = require('../iam_utils');

/**
 * https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetUser.html
 */
async function get_user(req, res) {

    const params = {
        username: req.body.user_name,
    };
    dbg.log1('IAM GET USER', params);
    const reply = await req.account_sdk.get_user(params);
    dbg.log2('get_user reply', reply);

    return {
        GetUserResponse: {
            GetUserResult: {
                User: {
                    UserId: reply.user_id,
                    Path: reply.path,
                    UserName: reply.username,
                    Arn: reply.arn,
                    CreateDate: iam_utils.format_iam_xml_date(reply.create_date),
                    PasswordLastUsed: iam_utils.format_iam_xml_date(reply.password_last_used),
                }
            },
            ResponseMetadata: {
                RequestId: req.request_id,
            }
        },
    };
}

module.exports = {
    handler: get_user,
    body: {
        type: 'xml',
    },
    reply: {
        type: 'xml',
    },
};
