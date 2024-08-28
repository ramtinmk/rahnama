import sqlite3

# Connect to the SQLite database
conn = sqlite3.connect('data/database.db')
cursor = conn.cursor()

# Example: Adding a new column called 'bio' of type TEXT to the 'users' table
try:
    # cursor.execute("ALTER TABLE users ADD COLUMN edited_times INTEGER DEFAULT 0;")
    # print("Column added successfully.")
    sql_query = """
    CREATE TABLE new_notifications(
    notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_username TEXT NOT NULL,
    to_username TEXT NOT NULL,
    kind TEXT CHECK(kind IN ('view', 'upvote','comment')) NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    post_id INTEGER NOT NULL,
    FOREIGN KEY (from_username) REFERENCES Users(username) ON DELETE CASCADE,
    FOREIGN KEY (to_username) REFERENCES Users(username) ON DELETE CASCADE,
    FOREIGN KEY (post_id) REFERENCES Posts(post_id) ON DELETE CASCADE
);

"""
    # sql_copy = """
    # INSERT INTO new_notifications(notification_id, from_username, to_username, kind, created_at, post_id)
    # SELECT notification_id, from_username, to_username, kind, created_at,0
    # FROM notifications
    # """
    # cursor.execute(sql_copy)

    # # Step 3: Drop the old table
    # cursor.execute("DROP TABLE notifications")

    # Step 4: Rename the new table to the original table name
    cursor.execute("ALTER TABLE Posts ADD COLUMN views DEFAULT 0;")
except sqlite3.OperationalError as e:
    print(f"An error occurred: {e}")

# Commit the changes
conn.commit()

# Close the connection
cursor.close()
conn.close()