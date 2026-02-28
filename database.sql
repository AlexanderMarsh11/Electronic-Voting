CREATE TABLE IF NOT EXISTS users (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  national_id_hash CHAR(64) NOT NULL UNIQUE,
  public_key_pem TEXT NOT NULL,
  district CHAR(1) NOT NULL,
  eligible TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS elections (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  scope ENUM('global','district') NOT NULL,
  district CHAR(1) NULL,
  filing_open DATETIME NOT NULL,
  filing_close DATETIME NOT NULL,
  ballot_open DATETIME NOT NULL,
  ballot_close DATETIME NOT NULL,
  public_key_pem TEXT NOT NULL,
  private_key_path VARCHAR(512) NOT NULL,
  status ENUM('draft','open','closed') NOT NULL DEFAULT 'open',
  created_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS candidates (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  election_id BIGINT NOT NULL,
  user_id BIGINT NOT NULL,
  display_name VARCHAR(120) NOT NULL,
  created_at DATETIME NOT NULL,
  UNIQUE KEY uniq_candidate (election_id, user_id),
  FOREIGN KEY (election_id) REFERENCES elections(id),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS votes (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  election_id BIGINT NOT NULL,
  credential_hash BINARY(32) NOT NULL,
  ciphertext LONGBLOB NOT NULL,
  ballot_hash BINARY(32) NOT NULL,
  submitted_at DATETIME NOT NULL,
  UNIQUE KEY uniq_vote (election_id, credential_hash),
  FOREIGN KEY (election_id) REFERENCES elections(id)
);

CREATE TABLE IF NOT EXISTS results (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  election_id BIGINT NOT NULL UNIQUE,
  results_json JSON NOT NULL,
  published_hashes JSON NOT NULL,
  published_at DATETIME NOT NULL,
  FOREIGN KEY (election_id) REFERENCES elections(id)
);