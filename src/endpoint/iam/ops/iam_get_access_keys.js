/* Copyright (C) 2024 NooBaa */
'use strict';

const dbg = require('../../../util/debug_module')(__filename);
const iam_utils = require('../iam_utils');

/**
 * https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAccessKeys.html
 */
async function list_access_keys(req, res) {

    const params = {
        marker: req.body.marker,
        max_items: req.body.max_items,
        username: req.body.user_name,
    };
    dbg.log1('IAM LIST ACCESS KEYS', params);
    const reply = await req.account_sdk.list_access_keys(params, req.account_sdk);
    dbg.log2('list_access_keys reply', reply);

    // GAP - I don't see the UserName and IsTruncated in the reply xml
    return {
        ListAccessKeysResponse: {
            ListAccessKeysResult: {
                UserName: reply.username,
                AccessKeyMetadata: reply.members.map(member => ({
                    member: {
                        UserName: member.username,
                        AccessKeyId: member.access_key,
                        Status: member.status,
                        CreateDate: iam_utils.format_iam_xml_date(member.create_date),
                    },
                })),
                IsTruncated: reply.is_truncated,
            },
            ResponseMetadata: {
                RequestId: req.request_id,
            }
        },
    };
}

module.exports = {
    handler: list_access_keys,
    body: {
        type: 'xml',
    },
    reply: {
        type: 'xml',
    },
};
