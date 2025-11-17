import socket
import sys
import random
import hashlib
from des_logic import run_des

P = 23
G = 5

def derive_des_key(shared_secret_int):
    s_bytes = str(shared_secret_int).encode('utf-8')
    
    hash_bytes = hashlib.sha256(s_bytes).digest()
    
    key_bytes = hash_bytes[:8]
    
    key_str = key_bytes.decode('latin-1')
    
    if len(key_str) != 8:
        raise Exception(f"Gagal menghasilkan kunci 8-karakter. Panjang: {len(key_str)}")
        
    return key_str


HOST = '127.0.0.1'
PORT = 65432

def start_server():
    """Berperan sebagai Device 1 (Server) - Menerima dulu, baru membalas."""
    
    print("--- Device 1 (Server) ---")
    print("Generating private key (a)...")
    a = random.getrandbits(256) 
    print("Generating public key (A = G^a mod P)...")
    A = pow(G, a, P) 

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Menunggu koneksi dari Device 2 di {HOST}:{PORT}...")
        conn, addr = s.accept()
        with conn:
            print(f"Terhubung dengan Device 2 di {addr}")

            print("Memulai pertukaran kunci Diffie-Hellman...")
            
            try:
                B_str = conn.recv(2048).decode('utf-8')
                B = int(B_str)
                print(f"Menerima kunci publik (B) dari Device 2.")
                print(f"Public Key B: {B}")
                conn.sendall(str(A).encode('utf-8'))
                print(f"Mengirim kunci publik (A) ke Device 2.")
                print(f"Public Key A: {A}")
                
                print("Menghitung shared secret (S = B^a mod P)...")
                S = pow(B, a, P)
                print(f"Shared Secret (S): {S}")    
                KEY = derive_des_key(S)
                print("\n*** Kunci DES berhasil disepakati! ***\n")
                print(f"DES Key: {KEY}\n")
                
            except Exception as e:
                print(f"Error saat pertukaran kunci: {e}")
                return
            
            print("Ketik 'q' untuk keluar kapan saja.\n")

            while True:
                data_hex = conn.recv(1024).decode('utf-8')
                if not data_hex:
                    print("Device 2 menutup koneksi.")
                    break
                
                try:
                    print(f"Encrypted Message from Device 2: {data_hex}")

                    decrypted_msg = run_des(data_hex, KEY, 'decrypt')
                    print(f"[Device 2]: {decrypted_msg}\n")
                    
                    if decrypted_msg.lower() == 'q':
                        print("Device 2 meminta keluar.")
                        break
                        
                except Exception as e:
                    print(f"Error dekripsi: {e}. Data diterima: {data_hex}")
                    continue 

                msg_to_send = input("[Device 1] Balas: ")
                
                encrypted_msg = run_des(msg_to_send, KEY, 'encrypt')
                print(f"Sending Encrypted Message: {encrypted_msg}\n")
               
                conn.sendall(encrypted_msg.encode('utf-8'))
                
                if msg_to_send.lower() == 'q':
                    print("Menutup koneksi.")
                    break

def start_client():
    """Berperan sebagai Device 2 (Client) - Mengirim dulu, baru menerima balasan."""
    
    print(f"--- Device 2 (Client) ---")
    print("Generating private key (b)...")
    b = random.getrandbits(256) 
    print("Generating public key (B = G^b mod P)...")
    B = pow(G, b, P) 
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT))
        except ConnectionRefusedError:
            print(f"Gagal terhubung ke {HOST}:{PORT}. Pastikan Device 1 (Server) sudah berjalan.")
            return
            
        print(f"Terhubung ke Device 1.")

        print("Memulai pertukaran kunci Diffie-Hellman...")
        
        try:
            s.sendall(str(B).encode('utf-8'))
            print(f"Mengirim kunci publik (B) ke Device 1.")
            print(f"Public Key B: {B}")
            A_str = s.recv(2048).decode('utf-8')
            A = int(A_str)
            print(f"Menerima kunci publik (A) dari Device 1.")
            print(f"Public Key A: {A}")
            print("Menghitung shared secret (S = A^b mod P)...")
            S = pow(A, b, P)
            print(f"Shared Secret (S): {S}")
            KEY = derive_des_key(S)
            print("\n*** Kunci DES berhasil disepakati! ***\n")
            print(f"DES Key: {KEY}\n")
            
        except Exception as e:
            print(f"Error saat pertukaran kunci: {e}")
            return
        
        print("Ketik 'q' untuk keluar kapan saja.\n")

        while True:
            msg_to_send = input("[Device 2] Kirim: ")
            
            encrypted_msg = run_des(msg_to_send, KEY, 'encrypt')
            print(f"Sending Encrypted Message: {encrypted_msg}")
            
            s.sendall(encrypted_msg.encode('utf-8'))
            
            if msg_to_send.lower() == 'q':
                print("Menutup koneksi.")
                break

            data_hex = s.recv(1024).decode('utf-8')
            if not data_hex:
                print("Device 1 menutup koneksi.")
                break

            try:
                print(f"Encrypted Message from Device 1: {data_hex}")

                decrypted_msg = run_des(data_hex, KEY, 'decrypt')
                print(f"[Device 1]: {decrypted_msg} \n")
                
                if decrypted_msg.lower() == 'q':
                    print("Device 1 meminta keluar.")
                    break
                    
            except Exception as e:
                print(f"Error dekripsi: {e}. Data diterima: {data_hex}")
                continue 

if __name__ == "__main__":
        
    choice = input("Pilih peran Anda (1=Device 1/Server, 2=Device 2/Client): ").strip()
    
    if choice == '1':
        start_server()
    elif choice == '2':
        start_client()
    else:
        print("Pilihan tidak valid. Masukkan '1' atau '2'.")