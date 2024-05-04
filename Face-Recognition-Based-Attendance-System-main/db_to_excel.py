import sqlite3
import pandas as pd

# Connect to the SQLite database
# Replace 'your_database.db' with the path to your database file
conn = sqlite3.connect('attendance.db')

# Query the data from the database
# Replace 'your_table' with the name of the table you want to export
query = "SELECT * FROM attendance"
df = pd.read_sql_query(query, conn)

# Write the data to an Excel file
# Replace 'output.xlsx' with the desired output file name
df.to_excel('attendance.xlsx', index=False)

# Close the database connection
conn.close()