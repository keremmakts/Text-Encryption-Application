import tkinter as tk
from tkinter import messagebox, ttk
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Sabit anahtar ve IV üretimi
key = get_random_bytes(16)  # AES-128 için 16 byte (128 bit) anahtar kullanıyoruz
iv = get_random_bytes(AES.block_size)  # CBC modunda kullanılacak sabit bir IV oluşturuyoruz

# Metin şifreleme fonksiyonu
def encrypt_text(plain_text):
    plain_text_bytes = plain_text.encode('utf-8')
    padded_text = pad(plain_text_bytes, AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Sabit IV kullanarak şifreleme yapılıyor
    cipher_text = cipher.encrypt(padded_text)
    return iv.hex() + cipher_text.hex()  # IV'yi şifreli metnin başına ekliyoruz

# Metin şifresini çözme fonksiyonu
def decrypt_text(cipher_text_hex):
    try:
        iv = bytes.fromhex(cipher_text_hex[:32])  # Şifrelenmiş metnin başındaki IV'yi alıyoruz
        cipher_text = bytes.fromhex(cipher_text_hex[32:])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plain_text_bytes = unpad(cipher.decrypt(cipher_text), AES.block_size)
        plain_text = plain_text_bytes.decode('utf-8')
        return plain_text
    except ValueError:
        messagebox.showerror("Hata", "Şifre çözme işlemi başarısız oldu. Lütfen geçerli bir şifreli metin girin.")

# Tkinter penceresi oluşturma
root = tk.Tk()
root.title("Metin Şifreleme Uygulaması")

# Dark tema renkleri
bg_color = "#2c3e50"  # Arka plan rengi
fg_color = "#ecf0f1"  # Yazı rengi
button_bg_color = "#16a085"  # Düğme arka plan rengi
button_fg_color = "#FFFFFF"  # Düğme yazı rengi

# Arayüz temasını ayarlama
root.configure(bg=bg_color)

# Ana pencerenin grid yapılandırması
root.columnconfigure(0, weight=1)
root.columnconfigure(1, weight=1)
root.rowconfigure(0, weight=1)
root.rowconfigure(1, weight=1)
root.rowconfigure(2, weight=1)
root.rowconfigure(3, weight=1)

# Metin etiketi
input_label = tk.Label(root, text="Metin:", bg=bg_color, fg=fg_color, font=("Arial", 12, "bold"))
input_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")

# Metin giriş kutusu
input_text = tk.Text(root, height=5, width=40, bg="#FFFFFF", fg="#000000", font=("Arial", 12))
input_text.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

# Şifreleme düğmesi
def encrypt_button_clicked(event=None):
    plain_text = input_text.get("1.0", "end-1c")
    if not plain_text.strip():
        messagebox.showerror("Hata", "Şifrelenecek metin giriniz.")
        return
    cipher_text = encrypt_text(plain_text)
    output_text.delete("1.0", tk.END)
    output_text.insert("1.0", cipher_text)

encrypt_button = ttk.Button(root, text="Şifrele", command=encrypt_button_clicked, style='TButton')
encrypt_button.grid(row=1, column=1, padx=10, pady=10, sticky="nsew")

# Şifreli metin etiketi
output_label = tk.Label(root, text="Şifreli Metin:", bg=bg_color, fg=fg_color, font=("Arial", 12, "bold"))
output_label.grid(row=2, column=0, padx=10, pady=10, sticky="w")

# Şifreli metin çıktı kutusu
output_text = tk.Text(root, height=5, width=40, bg="#FFFFFF", fg="#000000", font=("Arial", 12))
output_text.grid(row=2, column=1, padx=10, pady=10, sticky="nsew")

# Şifre çözme düğmesi
def decrypt_button_clicked(event=None):
    cipher_text_hex = output_text.get("1.0", "end-1c")
    if not cipher_text_hex.strip():
        messagebox.showerror("Hata", "Şifreli metin giriniz.")
        return
    plain_text = decrypt_text(cipher_text_hex)
    if plain_text:
        input_text.delete("1.0", tk.END)
        input_text.insert("1.0", plain_text)

decrypt_button = ttk.Button(root, text="Şifreyi Çöz", command=decrypt_button_clicked, style='TButton')
decrypt_button.grid(row=3, column=1, padx=10, pady=10, sticky="nsew")

# Metin ve şifreli metin etiketlerinin boyutunu ayarlama
output_text.bind("<Configure>", lambda e: output_label.config(wraplength=output_text.winfo_width()-20))
input_text.bind("<Configure>", lambda e: input_label.config(wraplength=input_text.winfo_width()-20))

# Pencereyi görüntüle
root.mainloop()
