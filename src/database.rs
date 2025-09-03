use std::sync::OnceLock;
use log::{info};
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;

static CONNECTION_POOL: OnceLock<Pool<SqliteConnectionManager>> = OnceLock::new();

pub fn init() {
    info!("Initializing database connection pool");
    CONNECTION_POOL
        .set(
            Pool::builder()
                .max_size(5)
                .build(SqliteConnectionManager::file("octuple.db"))
                .expect("Failed to create pool"),
        )
        .expect("Connection pool already initialized");
    let init_connection = get_connection();
    init_connection
        .execute(
            "CREATE TABLE IF NOT EXISTS keys (
                domain TEXT PRIMARY KEY NOT NULL,
                key BLOB NOT NULL
            )",
            [],
        )
        .expect("Failed to create keys table");
    init_connection
        .execute(
            "CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY NOT NULL,
                key BLOB NOT NULL
            )",
            [],
        )
        .expect("Failed to create keys table");
    init_connection
        // SOME OPTIONS ARE DISABLED FOR THE BETA RELEASE
        .execute(
            "CREATE TABLE IF NOT EXISTS spaces (
                name TEXT PRIMARY KEY NOT NULL,
                image TEXT NOT NULL
                /*
                public BOOLEAN NOT NULL
                hierarchy TEXT NOT NULL
                */
            )",
            [],
        )
        .expect("Failed to create space table");
    // DISABLED FOR BETA RELEASE
    /*
    init_connection
        .execute("CREATE TABLE IF NOT EXISTS roles (
                name TEXT NOT NULL,
                color BLOB NOT NULL,
                display BOOLEAN NOT NULL,
                space TEXT NOT NULL,
                PRIMARY KEY (name, space)
            )",
         [],
        )
        .expect("Failed to create roles table");
    */
    // DISABLED FOR BETA RELEASE
    /*
    init_connection
        .execute(
            "CREATE TABLE IF NOT EXISTS space_permissions (
                role TEXT NOT NULL,
                space TEXT NOT NULL,
                permission INTEGER NOT NULL,
                PRIMARY KEY (role, space, permission)
            )",
            [],
        )
        .expect("Failed to create permissions table");
     */
    init_connection
        // SOME OPTIONS ARE DISABLED FOR THE BETA RELEASE
        .execute(
            "CREATE TABLE IF NOT EXISTS rooms (
                name TEXT NOT NULL,
                space TEXT NOT NULL,
                PRIMARY KEY (name, space)
                /*
                federated BOOLEAN NOT NULL,
                encrypted BOOLEAN NOT NULL,
                */
            )",
            [],
        )
        .expect("Failed to create rooms table");
    // DISABLED FOR BETA RELEASE
    /*
    init_connection
        .execute(
            "CREATE TABLE IF NOT EXISTS room_permissions (
                role TEXT NOT NULL,
                room TEXT NOT NULL,
                permission INTEGER NOT NULL,
                PRIMARY KEY (role, room, permission)
            )",
            [],
        )
        .expect("Failed to create permissions table");
     */
    init_connection
        .execute(
            "CREATE TABLE IF NOT EXISTS members (
                space TEXT NOT NULL,
                user TEXT NOT NULL,
                PRIMARY KEY (space, user)
            )",
            [],
        )
        .expect("Failed to create members table");
    // DISABLED FOR BETA RELEASE
    /*
    init_connection
        .execute(
            "CREATE TABLE IF NOT EXISTS member_roles (
                space TEXT NOT NULL,
                user TEXT NOT NULL,
                role TEXT NOT NULL,
                PRIMARY KEY (space, user, role)
            )",
            [],
        )
        .expect("Failed to create member roles table");
    */
    init_connection
        .execute(
            "CREATE TABLE IF NOT EXISTS invites (
                space TEXT NOT NULL,
                creator TEXT NOT NULL,
                expiry INTEGER NOT NULL,
                code BLOB NOT NULL
            )",
            [],
        )
        .expect("Failed to create invites table");
    init_connection
        .execute(
            "CREATE TABLE IF NOT EXISTS messages (
                id BLOB NOT NULL,
                room TEXT NOT NULL,
                sender TEXT NOT NULL,
                content TEXT NOT NULL,
                PRIMARY KEY (id, room)
            )",
            [],
        )
        .expect("Failed to create messages table");
    info!("Database connection pool initialized successfully");
}

pub fn get_connection_pool() -> &'static Pool<SqliteConnectionManager> {
    CONNECTION_POOL
        .get()
        .expect("Connection pool not initialized")
}

pub fn get_connection() -> PooledConnection<SqliteConnectionManager> {
    get_connection_pool()
        .get()
        .expect("Failed to get connection from pool")
}
