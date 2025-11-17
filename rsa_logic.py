
def gcd(a, b):
    """Menghitung greatest common divisor (GCD) menggunakan Algoritma Euclidean."""
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    """
    Mencari modular multiplicative inverse 'd' dari 'e' mod 'phi'.
    Artinya, (e * d) % phi = 1.
    Menggunakan algoritma Extended Euclidean.
    """
    m0 = phi
    y = 0
    x = 1
    
    if (phi == 1):
        return 0
        
    while (e > 1):
        q = e // phi
        
        t = phi
        
        phi = e % phi
        e = t
        t = y
        
        y = x - q * y
        x = t
        
    if (x < 0):
        x = x + m0
        
    return x

def is_prime(n):
    """Pengecekan bilangan prima sederhana."""
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0 or n % 3 == 0: return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def generate_keypair():
    """
    Menghasilkan keypair RSA "mainan" (toy).
    Dalam implementasi nyata, p dan q harus prima besar dan acak.
    Di sini kita hardcode untuk kesederhanaan dan kecepatan.
    """
    p = 61
    q = 53
    
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("p dan q harus bilangan prima.")
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 17 
    
    if gcd(e, phi) != 1:
        raise ValueError("e dan phi(n) tidak coprime. Coba p/q/e yang lain.")
        
    d = mod_inverse(e, phi)
    
    return ((e, n), (d, n))