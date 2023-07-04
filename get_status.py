import sqlite3

def get_attendance_info(source_address):
    conn = sqlite3.connect("attendance.db")
    cursor = conn.cursor()

    cursor.execute("SELECT status, time FROM attendance WHERE source_address=?", (source_address,))
    record = cursor.fetchone()

    if record:
        status, time = record
        return status, time
    else:
        return None, None

def get_all_attendance_records():
    conn = sqlite3.connect("attendance.db")
    cursor = conn.cursor()

    cursor.execute("SELECT source_address, status, time FROM attendance")
    records = cursor.fetchall()

    return records


if __name__ == "__main__":
    choice = input("Enter 'A' to display all records or 'S' to search for a specific source address: ").upper()

    if choice == 'A':
        records = get_all_attendance_records()
        print("All attendance records:")
        for record in records:
            source_address, status, time = record
            print(f"Source Address: {source_address}\nStatus: {status}\nTime: {time}\n")
    elif choice == 'S':
        source_address = input("Enter the source address (phone number): ")
        status, time = get_attendance_info(source_address)

        if status and time:
            print(f"Status: {status}\nTime: {time}")
        else:
            print("No record found for the given source address.")
    else:
        print("Invalid input. Please enter 'A' or 'S'.")