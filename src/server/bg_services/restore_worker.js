/* Copyright (C) 2026 NooBaa */
'use strict';

const config = require('../../../config');
const dbg = require('../../util/debug_module')(__filename);
const MDStore = require('../object_services/md_store').MDStore;
const system_store = require('../system_services/system_store').get_instance();
const system_utils = require('../utils/system_utils');
const auth_server = require('../common_services/auth_server');
const server_rpc = require('../server_rpc');
const deep_archive_utils = require('../../util/deep_archive_utils');
const { destroy_source_stream } = require('../../util/object_utils');
const ObjectIO = require('../../sdk/object_io');
const map_deleter = require('../object_services/map_deleter');
const archive_server = require('./archive_server');
const P = require('../../util/promise');

class RestoreWorker {

    constructor({ name }) {
        this.name = name;
        this.marker = undefined;
        this.object_io = new ObjectIO(); // for writing STANDARD restore copies
    }

    async run_batch() {
        if (!this._can_run()) return;

        const { ongoing_objects, marker } = await MDStore.instance().find_objects_restore_status_ongoing(
            config.RESTORE_WORKER_BATCH_SIZE, this.marker);

        if (!ongoing_objects || ongoing_objects.length === 0) {
            this.marker = undefined;
            dbg.log0('RestoreWorker: no objects with restore_status.ongoing');
            return config.RESTORE_WORKER_EMPTY_DELAY;
        }

        const next_marker = ongoing_objects.length === config.RESTORE_WORKER_BATCH_SIZE ? marker : undefined;

        dbg.log0('RestoreWorker: checking restore status for objects:',
            ongoing_objects.map(o => o.key).join(', '));

        const { has_errors } = await this._handle_ongoing_restores(ongoing_objects);

        if (has_errors) {
            return config.RESTORE_WORKER_ERROR_DELAY;
        }
        this.marker = next_marker;
        return next_marker ? config.RESTORE_WORKER_BATCH_DELAY : config.RESTORE_WORKER_EMPTY_DELAY;
    }

    _can_run() {
        if (!system_store.is_finished_initial_load) {
            dbg.log0('RestoreWorker: system_store did not finish initial load');
            return false;
        }

        const system = system_store.data.systems[0];
        if (!system || system_utils.system_in_maintenance(system._id)) return false;

        return true;
    }

    async _handle_ongoing_restores(ongoing_objects) {
        const system = system_store.data.systems[0];
        const auth_token = auth_server.make_auth_token({
            system_id: system._id,
            account_id: system.owner._id,
            role: 'admin',
        });
        const rpc_client = server_rpc.rpc.new_client({ auth_token });

        let has_errors = false;
        await P.map_with_concurrency(config.RESTORE_WORKER_CONCURRENCY, ongoing_objects, async obj => {
            try {
                await this._handle_object_restore(obj, rpc_client);
            } catch (err) {
                dbg.error(`RestoreWorker: failed handling object ${obj.key} ${obj._id}:`, err);
                has_errors = true;
            }
        });

        return { has_errors };
    }

    async _handle_object_restore(obj, rpc_client) {
        const bucket = system_store.data.get_by_id(obj.bucket);
        if (!deep_archive_utils.is_remote_archive_object(obj, bucket)) {
            dbg.warn('RestoreWorker: skipping non-remote-archive object', obj.key, obj._id, obj.storage_class);
            return;
        }

        const { is_restored, size } = await rpc_client.archive.check_archive_restore_status(
            { bucket_id: obj.bucket, obj_id: obj._id });

        if (!is_restored) {
            dbg.log1('RestoreWorker: restore still ongoing', obj.key, String(obj._id));
            return;
        }

        const log_details = { key: obj.key, obj_id: String(obj._id), bucket: bucket.name.unwrap(), size };
        if (size > config.RESTORE_WORKER_LARGE_OBJECT_SIZE) {
            dbg.log0('RestoreWorker: large object restored on deep archive, using non-MPU path', log_details);
            await this._write_standard_restore_copy(obj, bucket, size, rpc_client); // temporary: MPU condition not implemented yet, fallback to the small objects (temporary)
        } else {
            dbg.log0('RestoreWorker: object restored on deep archive, writing STANDARD copy', log_details);
            await this._write_standard_restore_copy(obj, bucket, size, rpc_client);
        }
    }

    // 1. general validations and prepare the params
    // 2. in case of partial restore-copy, clear the previous restore-copy mappings (in case of retry)
    // 3. data: upload the restore-copy from the archive to STANDARD storage class
    // 4. metadata: update the restore_status (ongoing false + expiry_time)
    async _write_standard_restore_copy(obj, bucket, size, rpc_client) {
        const params = await this._prepare_restore_copy(obj, bucket, size, rpc_client);
        const copy_complete = await this._has_complete_restore_copy(obj, params.object_size);
        if (!copy_complete) {
            await this._clear_previous_restore_copy(obj, params.bucket_name);
            await this._upload_restore_copy_from_archive(obj, params);
        }
        const expires_on = deep_archive_utils.compute_restore_expiry(params.days);
        await this._update_restore_status(rpc_client, { bucket_name: params.bucket_name, key: obj.key, obj_id: obj._id, expires_on });
        dbg.log0('RestoreWorker: wrote STANDARD restore copy',
            { key: obj.key, obj_id: String(obj._id), bucket: params.bucket_name, size: params.object_size, expiry_time: expires_on });
    }

    async _prepare_restore_copy(obj, bucket, size, rpc_client) {
        const days = obj.restore_status?.days;
        if (!days) {
            throw new Error(`RestoreWorker: missing restore_status.days for object ${obj.key} ${obj._id}`);
        }

        const object_size = size ?? obj.size;
        if (!(object_size >= 0)) {
            throw new Error(`RestoreWorker: invalid object size for ${obj.key} ${obj._id}`);
        }

        return {
            days,
            bucket_name: bucket.name.unwrap(),
            object_size,
            rpc_client,
        };
    }

    async _has_complete_restore_copy(obj, object_size) {
        if (object_size === 0) {
            return !(await MDStore.instance().has_any_parts_for_object(obj));
        }
        const parts = await MDStore.instance().find_parts_sorted_by_start({ obj_id: obj._id });
        if (!parts.length) return false;

        let covered_until = 0; // the end of the contiguous byte range covered so far
        for (const part of parts) {
            if (part.start > covered_until) return false;
            if (part.end > covered_until) covered_until = part.end;
            if (covered_until >= object_size) return true;
        }
        return covered_until >= object_size;
    }

    // this function is used on retry of the restore-copy write
    // without clearing, a second upload_object_range can add another set of parts for the same ranges
    async _clear_previous_restore_copy(obj, bucket_name) {
        const has_parts = await MDStore.instance().has_any_parts_for_object(obj);
        if (!has_parts) return;
        dbg.log0('RestoreWorker: clearing previous restore-copy mappings before rewrite',
            { key: obj.key, obj_id: String(obj._id), bucket: bucket_name });
        await map_deleter.delete_object_mappings(obj);
    }

    async _upload_restore_copy_from_archive(obj, params) {
        const { bucket_name, object_size, rpc_client } = params;
        const source_stream = await archive_server.read_archive_object_stream({
            bucket_id: obj.bucket,
            obj_id: obj._id,
            size: object_size,
        });

        try {
            await this.object_io.upload_object_range({
                client: rpc_client,
                obj_id: obj._id,
                bucket: bucket_name,
                key: obj.key,
                start: 0,
                end: object_size,
                size: object_size,
                source_stream,
            });
        } catch (err) {
            dbg.error('RestoreWorker: failed writing STANDARD restore copy',
                { key: obj.key, obj_id: String(obj._id), bucket: bucket_name, size: object_size }, err);
            destroy_source_stream({ source_stream });
            throw err;
        }
    }

    async _update_restore_status(rpc_client, { bucket_name, key, obj_id, expires_on }) {
        // Retries for update_object_md after a successful restore-copy write
        const RESTORE_MD_UPDATE_ATTEMPTS = 3;
        const RESTORE_MD_UPDATE_DELAY_MS = 500;

        await P.retry({
            attempts: RESTORE_MD_UPDATE_ATTEMPTS,
            delay_ms: RESTORE_MD_UPDATE_DELAY_MS,
            func: () => rpc_client.object.update_object_md({
                bucket: bucket_name,
                key,
                obj_id,
                restore_status: {
                    ongoing: false,
                    expiry_time: expires_on.getTime(),
                },
            }),
            error_logger: err => dbg.warn('RestoreWorker: update_object_md failed, retrying',
                { key, obj_id: String(obj_id), bucket: bucket_name }, err),
        });
    }

}

exports.RestoreWorker = RestoreWorker;
