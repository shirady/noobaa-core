'use strict';

/**
 *
 * NODE API
 *
 * most are client (currently web client) talking to the web server
 * to work on node usually as admin.
 *
 * the heartbeat is sent from an agent to the web server
 *
 */
module.exports = {

    name: 'node_api',

    methods: {

        create_node: {
            method: 'POST',
            params: {
                $ref: '/node_api/definitions/node_config'
            },
            reply: {
                type: 'object',
                required: ['id', 'peer_id', 'token'],
                properties: {
                    id: {
                        type: 'string'
                    },
                    peer_id: {
                        type: 'string'
                    },
                    token: {
                        type: 'string'
                    }
                }
            },
            auth: {
                system: ['admin', 'create_node']
            }
        },

        read_node: {
            method: 'GET',
            params: {
                type: 'object',
                required: ['name'],
                properties: {
                    name: {
                        type: 'string'
                    }
                }
            },
            reply: {
                $ref: '/node_api/definitions/node_full_info'
            },
            auth: {
                system: 'admin'
            }
        },

        update_node: {
            method: 'PUT',
            params: {
                $ref: '/node_api/definitions/node_config'
            },
            auth: {
                system: 'admin'
            }
        },

        delete_node: {
            method: 'DELETE',
            params: {
                type: 'object',
                required: ['name'],
                properties: {
                    name: {
                        type: 'string',
                    },
                }
            },
            auth: {
                system: 'admin'
            }
        },

        read_node_maps: {
            method: 'GET',
            params: {
                type: 'object',
                required: ['name'],
                properties: {
                    name: {
                        type: 'string'
                    },
                    skip: {
                        type: 'integer'
                    },
                    limit: {
                        type: 'integer'
                    },
                }
            },
            reply: {
                type: 'object',
                required: ['node', 'objects'],
                properties: {
                    node: {
                        $ref: '/node_api/definitions/node_full_info'
                    },
                    objects: {
                        type: 'array',
                        items: {
                            type: 'object',
                            required: [],
                            properties: {
                                key: {
                                    type: 'string'
                                },
                                parts: {
                                    type: 'array',
                                    items: {
                                        $ref: '/object_api/definitions/object_part_info'
                                    }
                                }
                            }
                        }
                    }
                }
            },
            auth: {
                system: 'admin'
            }
        },

        list_nodes: {
            method: 'GET',
            params: {
                type: 'object',
                required: [],
                properties: {
                    query: {
                        type: 'object',
                        required: [],
                        properties: {
                            tier: {
                                type: 'string'
                            },
                            name: {
                                // regexp
                                type: 'string'
                            },
                            geolocation: {
                                // regexp
                                type: 'string'
                            },
                        }
                    },
                    skip: {
                        type: 'integer'
                    },
                    limit: {
                        type: 'integer'
                    },
                }
            },
            reply: {
                type: 'object',
                required: ['nodes'],
                properties: {
                    nodes: {
                        type: 'array',
                        items: {
                            $ref: '/node_api/definitions/node_full_info'
                        }
                    }
                }
            },
            auth: {
                system: 'admin'
            }
        },

        group_nodes: {
            method: 'GET',
            params: {
                type: 'object',
                required: [],
                properties: {
                    group_by: {
                        type: 'object',
                        required: [],
                        properties: {
                            tier: {
                                type: 'boolean'
                            },
                            geolocation: {
                                type: 'boolean'
                            },
                        }
                    },
                }
            },
            reply: {
                type: 'object',
                required: ['groups'],
                properties: {
                    groups: {
                        type: 'array',
                        items: {
                            type: 'object',
                            required: ['count'],
                            properties: {
                                tier: {
                                    type: 'string'
                                },
                                geolocation: {
                                    type: 'string'
                                },
                                count: {
                                    type: 'integer'
                                },
                                online: {
                                    type: 'integer'
                                },
                                storage: {
                                    $ref: '/common_api/definitions/storage_info'
                                },
                            }
                        }
                    }
                }
            },
            auth: {
                system: 'admin'
            }
        },



        heartbeat: {
            method: 'PUT',
            params: {
                type: 'object',
                required: [
                    'id',
                    'port',
                    'storage',
                ],
                properties: {
                    id: {
                        type: 'string'
                    },
                    geolocation: {
                        type: 'string'
                    },
                    ip: {
                        type: 'string'
                    },
                    port: {
                        type: 'integer'
                    },
                    addresses: {
                        type: 'array',
                        items: {
                            type: 'string'
                        }
                    },
                    storage: {
                        $ref: '/common_api/definitions/storage_info'
                    },
                    device_info: {
                        type: 'object',
                        additionalProperties: true,
                    },
                }
            },
            reply: {
                type: 'object',
                required: ['version', 'delay_ms'],
                properties: {
                    version: {
                        type: 'string'
                    },
                    delay_ms: {
                        type: 'integer'
                    },
                    storage: {
                        $ref: '/common_api/definitions/storage_info'
                    },
                }
            },
            auth: {
                system: ['admin', 'agent']
            }
        },

        n2n_signal: {
            method: 'POST',
            params: {
                type: 'object',
                required: ['target'],
                properties: {
                    target: {
                        $ref: '/common_api/definitions/block_address'
                    },
                    info: {
                        type: 'object',
                        additionalProperties: true
                    }
                }
            },
            reply: {
                type: 'object',
                required: [],
                properties: {
                    info: {
                        type: 'object',
                        additionalProperties: true
                    },
                }
            },
            auth: {
                system: ['admin', 'agent', 'user']
            }
        },

        self_test_to_node_via_web: {
            method: 'POST',
            params: {
                type: 'object',
                required: ['source', 'target', 'request_length', 'response_length'],
                properties: {
                    source: {
                        $ref: '/common_api/definitions/block_address'
                    },
                    target: {
                        $ref: '/common_api/definitions/block_address'
                    },
                    request_length: {
                        type: 'integer'
                    },
                    response_length: {
                        type: 'integer'
                    }
                },
            },
            auth: {
                system: ['admin', 'user']
            }
        },

    },


    definitions: {

        node_config: {
            type: 'object',
            required: ['name'],
            properties: {
                name: {
                    type: 'string',
                },
                tier: {
                    type: 'string',
                },
                is_server: {
                    type: 'boolean',
                },
                geolocation: {
                    type: 'string',
                },
                srvmode: {
                    $ref: '/node_api/definitions/srvmode'
                },
                storage_alloc: {
                    type: 'integer'
                },
            }
        },


        srvmode: {
            type: 'string',
            enum: ['connect', 'disabled', 'decommissioning', 'decommissioned']
        },

        node_full_info: {
            type: 'object',
            required: [
                'id',
                'name',
                'tier',
                'geolocation',
                'peer_id',
                'ip',
                'port',
                'addresses',
                'online',
                'heartbeat',
                'storage',
                'device_info',
            ],
            properties: {
                id: {
                    type: 'string'
                },
                name: {
                    type: 'string'
                },
                tier: {
                    type: 'string'
                },
                geolocation: {
                    type: 'string'
                },
                srvmode: {
                    $ref: '/node_api/definitions/srvmode'
                },
                peer_id: {
                    type: 'string'
                },
                ip: {
                    type: 'string'
                },
                port: {
                    type: 'integer'
                },
                addresses: {
                    type: 'array',
                    items: {
                        type: 'string'
                    }
                },
                online: {
                    type: 'boolean',
                },
                heartbeat: {
                    type: 'integer',
                    format: 'idate',
                },
                storage: {
                    $ref: '/common_api/definitions/storage_info'
                },
                device_info: {
                    type: 'object',
                    additionalProperties: true,
                },
            }
        }

    }

};
