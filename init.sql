-- init.sql for the ssh honeypot database
CREATE DATABASE ssh_honeypot;
\c ssh_honeypot;

CREATE TYPE auth_type AS ENUM ('password', 'none', 'publickey');

CREATE TABLE IF NOT EXISTS credentials
(
    timestamp   TIMESTAMP WITH TIME ZONE    NOT NULL,
    client_ip   INET                        NOT NULL,
    port        INTEGER                     NOT NULL,
    auth_type   auth_type                   NOT NULL,
    username    TEXT                        NOT NULL,
    secret      TEXT,
    UNIQUE(username, secret)
);

CREATE TABLE IF NOT EXISTS clients
(
    client_ip   INET    PRIMARY KEY
);