import sqlite3

from exception_types import DBException


class UserType:
    NOT_A_USER = 0
    USER = 1
    ADMIN = 2


class UserDB:
    def __init__(self):
        try:
            self.conn = sqlite3.connect('users.db', isolation_level=None)
            self.cur = self.conn.cursor()
        except:
            raise DBException('connection exception')
    # with method need it
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cur.close()
        self.conn.close()

    # check if user exists
    def is_a_user(self, username, password):
        self.cur.execute("SELECT 1 FROM Users WHERE username==? AND Password==? LIMIT 1", (username, password))
        if self.cur.fetchone():  # An empty result evaluates to False.
            print("User: ", username, ":", password)
            return True
        else:
            return False

    # insert a new user to Users db
    def insert_user(self, username, password):
        try:
            self.cur.execute("INSERT INTO Users(username, password) VALUES (?, ?)", (username, password))
        except sqlite3.IntegrityError as e:
            raise DBException
        print("User was inserted")

    # delete user from Users db
    def delete_user(self, username):
        count_rows = 0
        try:
            count_rows = self.cur.execute("DELETE FROM Users WHERE username=?", (username,)).rowcount
        except sqlite3.IntegrityError as e:
            raise DBException
        print(count_rows, "users was deleted")
        return count_rows
