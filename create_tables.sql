CREATE TABLE users (
    id Integer PRIMARY KEY AUTO_INCREMENT,
    username Varchar(100) NOT NULL UNIQUE,
    password Varchar(256) NOT NULL,
    email Varchar(320) UNIQUE,
)