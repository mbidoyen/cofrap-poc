CREATE TABLE IF NOT EXISTS users (
    id        SERIAL PRIMARY KEY,
    username  VARCHAR(64)  UNIQUE NOT NULL,
    email     TEXT         NOT NULL,
    password  TEXT         NOT NULL,
    mfa       TEXT         NOT NULL,
    gendate   BIGINT       NOT NULL,
    expired   SMALLINT     DEFAULT 0
);
