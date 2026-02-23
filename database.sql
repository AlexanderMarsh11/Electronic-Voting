#database creation

CREATE DATABASE electronic_voting;
USE electronic_voting;

#Users table

CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    hashed_national_id CHAR(64) NOT NULL,  -- SHA-256
    voting_district ENUM('DistrictA','DistrictB') NOT NULL,
    public_key TEXT NOT NULL,               -- Public Key 
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

# Elections table
CREATE TABLE elections (
    election_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    election_type ENUM('FPTP','RankedChoice') DEFAULT 'FPTP',
    start_date DATETIME NOT NULL,
    end_date DATETIME NOT NULL,
    is_active BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

#Candidates table
CREATE TABLE candidates (
    candidate_id INT AUTO_INCREMENT PRIMARY KEY,
    election_id INT NOT NULL,
    name VARCHAR(255) NOT NULL,
    votes_received INT DEFAULT 0,
    FOREIGN KEY (election_id) REFERENCES elections(election_id) ON DELETE CASCADE
);

# Voters table
CREATE TABLE votes (
    vote_id INT AUTO_INCREMENT PRIMARY KEY,
    election_id INT NOT NULL,
    hashed_ballot CHAR(64) NOT NULL,  -- SHA-256 ballot
    ppk_hash CHAR(64) NOT NULL,       -- SHA-256 PPK file
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (election_id) REFERENCES elections(election_id) ON DELETE CASCADE
);


CREATE INDEX idx_votes_election ON votes(election_id);
CREATE INDEX idx_users_district ON users(voting_district);

ALTER TABLE votes ADD UNIQUE (election_id, ppk_hash);