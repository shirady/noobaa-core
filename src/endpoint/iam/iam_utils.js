/* Copyright (C) 2016 NooBaa */
'use strict';

const s3_utils = require('../s3/s3_utils');

const AWS_EMPTY_PATH = '/';
const AWS_NOT_USED = 'N/A'; // can be used in case the region or the service name were not used

/**
 * format_iam_xml_date return the date without milliseconds
 * @param {any} input
 */
function format_iam_xml_date(input) {
    const date_iso = s3_utils.format_s3_xml_date(input);
    const date_iso_no_zeros = date_iso.replace(/\.\d+/, ""); // remove the milliseconds zeros:
    return date_iso_no_zeros;
}

/**
 * create_arn creates the AWS ARN for user
 * see: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-arns
 * @param {string} account_id
 * @param {string} username
 * @param {string} path (AWS Path)
 */
function create_arn(account_id, username, path) {
    const basic_structure = `arn:aws:iam:${account_id}:user`;
    if (path && path !== AWS_EMPTY_PATH) {
        let arn_with_path = `${basic_structure}/${path}/${username}`;
        // in case the path contains leading or ending slash, we want to replace the double slash
        arn_with_path = arn_with_path.replaceAll("//", "/");
        return arn_with_path;
    }
    return `${basic_structure}/${username}`;
}

// EXPORTS
exports.format_iam_xml_date = format_iam_xml_date;
exports.create_arn = create_arn;
exports.AWS_EMPTY_PATH = AWS_EMPTY_PATH;
exports.AWS_NOT_USED = AWS_NOT_USED;
