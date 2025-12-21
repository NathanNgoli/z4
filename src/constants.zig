const std = @import("std");

pub const MAX_OBJECT_SIZE: u64 = 5 * 1024 * 1024 * 1024;
pub const MAX_REQUEST_HEADER_SIZE: usize = 32 * 1024;
pub const STREAM_BUFFER_SIZE: usize = 64 * 1024;
pub const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 300_000;
pub const DEFAULT_VIRTUAL_NODES: usize = 150;
pub const REPLICATION_FACTOR: usize = 3;
pub const MIN_ENCRYPTION_KEY_LENGTH: usize = 32;
pub const GOSSIP_INTERVAL_MS: u64 = 1000;
pub const MAX_KEY_LENGTH: usize = 1024;
pub const MAX_BUCKET_NAME_LENGTH: usize = 63;
pub const MIN_BUCKET_NAME_LENGTH: usize = 3;
pub const MAX_REQUEST_LINE_LENGTH: usize = 8192;
pub const LIST_OBJECTS_MAX_KEYS: usize = 1000;

pub const DEFAULT_HTTP_PORT: u16 = 8080;
pub const DEFAULT_GOSSIP_PORT: u16 = 8081;
pub const DEFAULT_DATA_PATH = "data";
pub const DEFAULT_NODE_ID = "node1";
pub const DEFAULT_OWNER_ID = "z4-owner";

pub const ACCESS_KEY_ID_LENGTH: usize = 20;
pub const SECRET_KEY_LENGTH: usize = 32;
pub const MAX_PERMISSIONS_FILE_SIZE: usize = 65536;
pub const MAX_KEY_FILE_SIZE: usize = 4096;

pub const LIFECYCLE_INTERVAL_MS: u64 = 60000;
pub const REQUEST_BUFFER_SIZE: usize = 65536;
pub const COPY_BUFFER_SIZE: usize = 65536;
pub const GOSSIP_BUFFER_SIZE: usize = 4096;
pub const LOG_BUFFER_SIZE: usize = 4096;
pub const RESPONSE_BUFFER_INITIAL_CAPACITY: usize = 1024;
pub const GOSSIP_PACKET_SIZE: usize = 1024;

pub const RATE_LIMIT_IP_RPS: f64 = 100.0;
pub const RATE_LIMIT_IP_BURST: f64 = 200.0;
pub const RATE_LIMIT_KEY_RPS: f64 = 1000.0;
pub const RATE_LIMIT_KEY_BURST: f64 = 2000.0;

pub const MIN_DISK_FREE_SPACE: u64 = 100 * 1024 * 1024;

pub const GOSSIP_HMAC_SIZE: usize = 32;
