/* Copyright (C) 2024 NooBaa */
'use strict';

const dbg = require('../../../util/debug_module')(__filename);
const iam_utils = require('../iam_utils');

/**
 * https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateUser.html
 */
async function create_user(req, res) {

    const params = {
        path: req.body.path,
        username: req.body.user_name,
    };
    dbg.log1('IAM CREATE USER', params);
    const reply = await req.account_sdk.create_user(params, req.account_sdk);
    dbg.log2('create_user reply', reply);

    return {
        CreateUserResponse: {
            CreateUserResult: {
                User: {
                    Path: reply.path ? reply.path : iam_utils.AWS_EMPTY_PATH,
                    UserName: reply.username,
                    UserId: reply.user_id,
                    Arn: reply.arn,
                    CreateDate: iam_utils.format_iam_xml_date(reply.create_date),
                }
            },
            ResponseMetadata: {
                RequestId: req.request_id,
            }
        }
    };
}

module.exports = {
    handler: create_user,
    body: {
        type: 'xml',
    },
    reply: {
        type: 'xml',
    },
};
