import socket
import sys
import random
import hashlib
from des_logic import run_des
from rsa_logic import generate_keypair  

def derive_des_key(shared_secret_int):
    """Fungsi ini tetap sama, tidak perlu diubah."""
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
    """Berperan sebagai Device 1 (Server) - Membuat Keypair RSA."""
    
    print("--- Device 1 (Server) ---")
    print("Generating RSA keypair (p=61, q=53)...")
    try:
        public_key, private_key = generate_keypair()
        e, n = public_key
        d, _ = private_key
        print(f"Public Key (e, n): ({e}, {n})")
        print(f"Private Key (d, n): ({d}, {n})")
    except Exception as e_gen:
        print(f"Error saat generate key: {e_gen}")
        return

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Menunggu koneksi dari Device 2 di {HOST}:{PORT}...")
        conn, addr = s.accept()
        with conn:
            print(f"Terhubung dengan Device 2 di {addr}")

            print("Memulai pertukaran kunci RSA...")
            
            try:
                # 1. Kirim public key (e,n) ke Device 2
                conn.sendall(f"{e},{n}".encode('utf-8'))
                print(f"Mengirim kunci publik (e,n) ke Device 2.")

                # 2. Terima 'C' (secret terenkripsi) dari Device 2
                C_str = conn.recv(2048).decode('utf-8')
                if not C_str:
                    print("Device 2 menutup koneksi sebelum pertukaran kunci selesai.")
                    return
                C = int(C_str)
                print(f"Menerima secret terenkripsi (C) dari Device 2.")
                
                # 3. Dekripsi C untuk mendapatkan S menggunakan private key (d)
                print("Mendekripsi C menggunakan kunci privat (d,n) ...")
                S = pow(C, d, n)
                
                # 4. Hasilkan Kunci DES dari S
                KEY = derive_des_key(S)
                print(f"\n*** Shared Secret (S) = {S} ***")
                print(f"*** Kunci DES yang Dihasilkan: {repr(KEY)} ***") 
                print("*** Kunci DES berhasil disepakati! ***\n")
                
            except Exception as e_key:
                print(f"Error saat pertukaran kunci: {e_key}")
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
                        
                except Exception as e_dec:
                    print(f"Error dekripsi: {e_dec}. Data diterima: {data_hex}")
                    continue 

                msg_to_send = input("[Device 1] Balas: ")
                
                encrypted_msg = run_des(msg_to_send, KEY, 'encrypt')
                print(f"Sending Encrypted Message: {encrypted_msg}\n")
               
                conn.sendall(encrypted_msg.encode('utf-8'))
                
                if msg_to_send.lower() == 'q':
                    print("Menutup koneksi.")
                    break

def start_client():
    """Berperan sebagai Device 2 (Client) - Mengenkripsi secret S."""
    
    print(f"--- Device 2 (Client) ---")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT))
        except ConnectionRefusedError:
            print(f"Gagal terhubung ke {HOST}:{PORT}. Pastikan Device 1 (Server) sudah berjalan.")
            return
            
        print(f"Terhubung ke Device 1.")
        print("Memulai pertukaran kunci RSA...")
        
        try:
            # 1. Terima public key (e,n) dari Device 1
            e_n_str = s.recv(2048).decode('utf-8')
            if not e_n_str:
                print("Device 1 menutup koneksi sebelum pertukaran kunci selesai.")
                return
            e, n = map(int, e_n_str.split(','))
            print(f"Menerima kunci publik (e, n) = ({e}, {n}) dari Device 1.")

            # 2. Generate shared secret acak (S)
            S = random.randint(1, n - 1) # S harus < n
            print(f"Menghasilkan shared secret acak (S) = {S}")
            
            # 3. Enkripsi S menggunakan public key (e,n) -> C
            print("Mengenkripsi S menggunakan kunci publik (e,n) ...")
            C = pow(S, e, n)
            
            # 4. Kirim C ke Device 1
            s.sendall(str(C).encode('utf-8'))
            print(f"Mengirim secret terenkripsi (C) ke Device 1.")
            
            # 5. Hitung Kunci DES
            KEY = derive_des_key(S)
            print(f"\n*** Shared Secret (S) = {S} ***") 
            print(f"*** Kunci DES yang Dihasilkan: {repr(KEY)} ***") 
            print("*** Kunci DES berhasil disepakati! ***\n")
            
        except Exception as e_key:
            print(f"Error saat pertukaran kunci: {e_key}")
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
                    
            except Exception as e_dec:
                print(f"Error dekripsi: {e_dec}. Data diterima: {data_hex}")
                continue 

if __name__ == "__main__":
    choice = input("Pilih peran Anda (1=Device 1/Server, 2=Device 2/Client): ").strip()
    
    if choice == '1':
        start_server()
    elif choice == '2':
        start_client()
    else:
        print("Pilihan tidak valid. Masukkan '1' atau '2'.")