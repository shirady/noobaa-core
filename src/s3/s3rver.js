'use strict';
require('../util/panic');

// load .env file before any other modules so that it will contain
// all the arguments even when the modules are loading.
console.log('loading .env file');
require('dotenv').load();

var _ = require('lodash');
var P = require('../util/promise');
var fs = require('fs');
var util = require('util');
var http = require('http');
var https = require('https');
var express = require('express');
var dbg = require('../util/debug_module')(__filename);
var argv = require('minimist')(process.argv);
var pem = require('../util/pem');
var s3app = require('./app');
var cluster = require('cluster');
var numCPUs = require('os').cpus().length;

var params = argv;
var certificate;
if (cluster.isMaster && process.env.S3_CLUSTER_DISABLED !== 'true') {
    // Fork workers.
    for (var i = 0; i < numCPUs; i++) {
        console.warn('Spawning S3 Server', i + 1);
        cluster.fork();
    }

    cluster.on('exit', function(worker, code, signal) {
        console.log('worker ' + worker.process.pid + ' died');
    });
} else {
    dbg.set_process_name('S3rver');
    P.nfcall(fs.readFile, 'agent_conf.json')
        .then(function(data) {
            var agent_conf = JSON.parse(data);
            dbg.log0('using agent_conf.json', util.inspect(agent_conf));
            params = _.defaults(params, agent_conf);
            return;
        }).then(null, function(err) {
            dbg.log0('cannot find configuration file. Using defaults.' + err);
            //Just in case part of the information is missing, add default params.
            params = _.defaults(params, {
                port: 80,
                ssl_port: 443,
            });
            return P.nfcall(pem.createCertificate.bind(pem), {
                days: 365 * 100,
                selfSigned: true
            });
        })
        .then(function(certificate_arg) {
            certificate = certificate_arg;

            // Workers can share any TCP connection
            // In this case its a HTTP server
            var app = express();
            // copied from s3rver. not sure why. but copy.
            app.disable('x-powered-by');

            app.use('/', s3app(params));

            return new P(function(resolve, reject) {
                    dbg.log0('Starting HTTP', params.port);
                    http.createServer(app)
                        .on('connection', connection_setup)
                        .listen(params.port, function(err) {
                            if (err) {
                                dbg.error('HTTP listen', err);
                                reject(err);
                            } else {
                                resolve();
                            }
                        });
                }).then(function() {
                    return new P(function(resolve, reject) {
                        dbg.log0('Starting HTTPS', params.ssl_port);
                        https.createServer({
                                key: certificate.serviceKey,
                                cert: certificate.certificate
                            }, app)
                            .on('connection', connection_setup)
                            .listen(params.ssl_port, function(err) {
                                if (err) {
                                    dbg.error('HTTPS listen', err);
                                    reject(err);
                                } else {
                                    resolve();
                                }
                            });
                    });
                }),
                function(err) {
                    dbg.log0('S3RVER ERROR (1)', err.stack || err);
                };
        }).then(null, function(err) {
            dbg.log0('S3RVER ERROR (2)', err.stack || err);
        });
}

function connection_setup(socket) {
    // this is an attempt to read from the socket in large chunks,
    // but it seems like it has no effect and we still get small chunks
    socket._readableState.highWaterMark = 1024 * 1024;
    socket.setNoDelay(true);
}
