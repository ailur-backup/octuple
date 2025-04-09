use std::sync::OnceLock;
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;

static CONNECTION_POOL: OnceLock<Pool<SqliteConnectionManager>> = OnceLock::new();

pub fn init() {
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
        .execute(
            "CREATE TABLE IF NOT EXISTS space (
                name TEXT PRIMARY KEY NOT NULL,
                public BOOLEAN NOT NULL
            )",
            [],
        )
        .expect("Failed to create space table");
    init_connection
        .execute(
            "CREATE TABLE IF NOT EXISTS members (
                space TEXT NOT NULL,
                user TEXT NOT NULL,
                PRIMARY KEY (space, user),
                FOREIGN KEY (space) REFERENCES space(name)
            )",
            [],
        )
        .expect("Failed to create members table");
    init_connection
        .execute("CREATE TABLE IF NOT EXISTS roles (
            name TEXT NOT NULL,
            color BLOB NOT NULL,
            display BOOLEAN NOT NULL,
            space TEXT NOT NULL,
            PRIMARY KEY (name, space),
            FOREIGN KEY (space) REFERENCES space(name)
        )",
         [],
        )
        .expect("Failed to create roles table");
    init_connection
        .execute(
            "CREATE TABLE IF NOT EXISTS space_permissions (
                role TEXT NOT NULL,
                space TEXT NOT NULL,
                permission INTEGER NOT NULL,
                PRIMARY KEY (role, space, permission),
                FOREIGN KEY (role) REFERENCES roles(name),
                FOREIGN KEY (space) REFERENCES space(name)
            )",
            [],
        )
        .expect("Failed to create permissions table");
    init_connection
        .execute(
            "CREATE TABLE IF NOT EXISTS rooms (
                name TEXT NOT NULL,
                federated BOOLEAN NOT NULL,
                encrypted BOOLEAN NOT NULL,
                space TEXT NOT NULL,
                PRIMARY KEY (name, space),
                FOREIGN KEY (space) REFERENCES space(name)
            )",
            [],
        )
        .expect("Failed to create rooms table");
    init_connection
        .execute(
            "CREATE TABLE IF NOT EXISTS room_permissions (
                role TEXT NOT NULL,
                room TEXT NOT NULL,
                permission INTEGER NOT NULL,
                PRIMARY KEY (role, room, permission),
                FOREIGN KEY (role) REFERENCES roles(name),
                FOREIGN KEY (room) REFERENCES rooms(name)
            )",
            [],
        )
        .expect("Failed to create permissions table");
    init_connection
        .execute(
            "CREATE TABLE IF NOT EXISTS messages (
                id BLOB NOT NULL,
                room TEXT NOT NULL,
                sender TEXT NOT NULL,
                PRIMARY KEY (id, room),
                FOREIGN KEY (room) REFERENCES rooms(name)
            )",
            [],
        )
        .expect("Failed to create messages table");
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
