from db_connection import db, cursor

# -------- USERS --------
def add_user(hashed_id, district, public_key):
    sql = "INSERT INTO users (hashed_national_id, voting_district, public_key) VALUES (%s, %s, %s)"
    cursor.execute(sql, (hashed_id, district, public_key))
    db.commit()

def get_user(hashed_id):
    sql = "SELECT * FROM users WHERE hashed_national_id=%s"
    cursor.execute(sql, (hashed_id,))
    return cursor.fetchone()


# -------- ELECTIONS --------
def add_election(name, election_type, start_date, end_date):
    sql = "INSERT INTO elections (name, election_type, start_date, end_date) VALUES (%s, %s, %s, %s)"
    cursor.execute(sql, (name, election_type, start_date, end_date))
    db.commit()

def get_active_elections():
    sql = "SELECT * FROM elections WHERE is_active=TRUE"
    cursor.execute(sql)
    return cursor.fetchall()


# -------- CANDIDATES --------
def add_candidate(election_id, name):
    sql = "INSERT INTO candidates (election_id, name) VALUES (%s, %s)"
    cursor.execute(sql, (election_id, name))
    db.commit()

def get_candidates(election_id):
    sql = "SELECT * FROM candidates WHERE election_id=%s"
    cursor.execute(sql, (election_id,))
    return cursor.fetchall()


# -------- VOTES --------
def add_vote(election_id, hashed_ballot, ppk_hash):
    sql = "INSERT INTO votes (election_id, hashed_ballot, ppk_hash) VALUES (%s, %s, %s)"
    cursor.execute(sql, (election_id, hashed_ballot, ppk_hash))
    db.commit()

def get_votes(election_id):
    sql = "SELECT * FROM votes WHERE election_id=%s"
    cursor.execute(sql, (election_id,))
    return cursor.fetchall()