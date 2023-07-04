import logging
import smpplib.client
import smpplib.gsm
import smpplib.consts
import time
import chardet
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from base64 import b64encode, b64decode
import sqlite3


class AttendanceDB():
    def __init__(self):
        self.conn = self.setup_database()

    def setup_database(self):
        conn = sqlite3.connect("attendance.db")
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS attendance (
            source_address TEXT PRIMARY KEY,
            status TEXT,
            time TEXT
        )
        """)

        conn.commit()
        return conn

    def insert_data(self,conn, decrypted_message, source_address):
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM attendance WHERE source_address=?", (source_address,))
        record = cursor.fetchone()

        status = ""
        time_str = ""
        if "Arrival" in decrypted_message:
            status = "Arrival"
            time_str = decrypted_message.split("Arrival")[1]
        elif "Exit" in decrypted_message:
            status = "Exit"
            time_str = decrypted_message.split("Exit")[1]

        if record:
            cursor.execute("""
            UPDATE attendance SET status=?, time=? WHERE source_address=?
            """, (status, time_str, source_address))
        else:
            cursor.execute("""
            INSERT INTO attendance (source_address, status, time) VALUES (?, ?, ?)
            """, (source_address, status, time_str))

        conn.commit()

class SMPP_Message_handler():
    def __init__(self):
        self.db = AttendanceDB()
    
    def aes_encrypt(self,message, key):
        iv = b'\x00' * AES.block_size
        cipher = AES.new(key.encode("utf-8"), AES.MODE_CBC, iv=iv)
        ciphertext = cipher.encrypt(pad(message.encode("utf-8"), AES.block_size))
        return b64encode(ciphertext).decode('utf-8')

    def aes_decrypt(self,ciphertext, key):
        iv = b'\x00' * AES.block_size
        data = b64decode(ciphertext)
        cipher = AES.new(key.encode("utf-8"), AES.MODE_CBC, iv=iv)
        decrypted_data = cipher.decrypt(data)
        return unpad(decrypted_data, AES.block_size).decode('utf-8')

    def sha256_hash(self,message):
        hasher = SHA256.new()
        hasher.update(message.encode('utf-8'))
        return hasher.hexdigest()

    def send_sms(self,client, src_addr, dst_addr, message):
        # Send SMS
        parts, encoding_flag, msg_type_flag = smpplib.gsm.make_parts(message)

        for part in parts:
            pdu = client.send_message(
                source_addr_ton=smpplib.consts.SMPP_TON_INTL,
                source_addr_npi=smpplib.consts.SMPP_NPI_ISDN,
                source_addr=src_addr,
                dest_addr_ton=smpplib.consts.SMPP_TON_INTL,
                dest_addr_npi=smpplib.consts.SMPP_NPI_ISDN,
                destination_addr=dst_addr,
                short_message=part,
                data_coding=encoding_flag,
                esm_class=msg_type_flag,
                registered_delivery=True,
            )
            print(f"SMS sent with PDU: {pdu}")

    def handle_incoming_sms(self,pdu, client):
        print(f"Incoming SMS PDU: {pdu}")
        source_address = pdu.source_addr.decode()
        print(f"Source address: {source_address}")
        if str(source_address) != "11111":
            print(f"Destination address: {pdu.destination_addr.decode()}")
            encrypted_message = pdu.short_message.decode("utf-8")
            print(f"Encrypted message content: {encrypted_message}")
            encrypted_message = str(encrypted_message).split("\x02\x02")[1]
            encrypted_message_bytes = encrypted_message.encode("iso-8859-1")
            print(f'processed enc message : {encrypted_message}')
            key = "a7b2c3d4e5f6g789abcdef0123456789" 
            #key = b"a7b2c3d4e5f6g789abcdef0123456789"  # Convert the key to a bytes object
            decrypted_message = self.aes_decrypt(encrypted_message_bytes, key)
            print(f"Decrypted message content: {decrypted_message}")

            self.db.insert_data(self.db.conn,decrypted_message,source_address)

            hashed_message = self.sha256_hash(decrypted_message)
            hashed_message = hashed_message + " | AFTSTC"
            
            encrypted_feedback = self.aes_encrypt(hashed_message, key)
            self.send_sms(client, pdu.destination_addr.decode(), source_address, f'$${encrypted_feedback}$$')

    def receive_sms(self,client):
        while True:
            try:
                client.set_message_received_handler(lambda pdu: self.handle_incoming_sms(pdu, client))
                print("Waiting for incoming SMS...")
                client.listen()
            except KeyboardInterrupt:
                print("Stopping listener...")
                break
            except Exception as e:
                print(f"Error occurred: {e}")
                print("Reconnecting...")
                time.sleep(5)
                client.connect()
                client.bind_transceiver(system_id=username, password=password)

    def send_and_receive_sms(self,host, port, username, password, src_addr):
        with smpplib.client.Client(host, port) as client:
            client.connect()
            client.bind_transceiver(system_id=username, password=password)
            self.receive_sms(client)
            client.unbind()
            client.disconnect()



smpp_handler = SMPP_Message_handler()
host = '192.168.1.143'
port = 9500
username = "smppuser"
password = "aVbpZzpt"
src_addr = '9102211824'
smpp_handler.send_and_receive_sms(host, port, username, password, src_addr)