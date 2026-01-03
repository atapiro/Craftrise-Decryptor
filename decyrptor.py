import json
import base64
import customtkinter as ctk
from tkinter import scrolledtext
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from tkinterdnd2 import TkinterDnD, DND_FILES
import os

# --- Decrypt fonksiyonları ---
def decrypt_base64(encoded_str):
    try:
        decoded_bytes = base64.b64decode(encoded_str)
        return decoded_bytes.decode("utf-8")
    except Exception:
        return encoded_str

def decrypt_rise_version(s):
    try:
        s1 = decrypt_base64(s)
        s2 = decrypt_base64(s1)
        prefix = "3ebi2mclmAM7Ao2"
        suffix = "KweGTngiZOOj9d6"
        if not (s2.startswith(prefix) and s2.endswith(suffix)):
            return s2
        substring = s2[len(prefix): len(s2) - len(suffix)]
        final = decrypt_base64(substring)
        return final
    except Exception:
        return s

def decrypt_aes(encrypted_base64):
    try:
        key = "2640023187059250".encode("utf-8")
        encrypted_data = base64.b64decode(encrypted_base64)
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        return decrypted_data.decode("utf-8")
    except Exception:
        return ""

def decrypt_password(encrypted_pass):
    decrypted_aes = decrypt_aes(encrypted_pass)
    if not decrypted_aes:
        return ""
    result = decrypt_rise_version(decrypted_aes)
    if "#" in result:
        return result.split("#")[0]
    return result

# --- Fonksiyonlar ---
def coz_config():
    try:
        raw_json = txt_input.get("1.0", "end").strip()
        config_data = json.loads(raw_json)
    except Exception as e:
        lbl_result.configure(text=f"❌ JSON okunamadı: {e}", text_color="red")
        return

    username = config_data.get("rememberName") or config_data.get("username") or ""
    encrypted_password = config_data.get("rememberPass") or config_data.get("encrypted_password") or ""

    if not encrypted_password:
        lbl_result.configure(text="⚠️ Şifre bulunamadı!", text_color="orange")
        return

    password = decrypt_password(encrypted_password)
    lbl_result.configure(text=f"👤 Username: {username}\n🔑 Password: {password}", text_color="green")

def coz_aes():
    data = txt_input.get("1.0", "end").strip()
    result = decrypt_aes(data)
    lbl_result.configure(text=f"AES Çözüm Sonucu:\n{result}", text_color="cyan")

def coz_base64():
    data = txt_input.get("1.0", "end").strip()
    result = decrypt_base64(data)
    lbl_result.configure(text=f"Base64 Çözüm Sonucu:\n{result}", text_color="purple")

def copy_result():
    text = lbl_result.cget("text")
    app.clipboard_clear()
    app.clipboard_append(text)
    app.update()

# Dosya sürükle-bırak
def load_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
            txt_input.delete("1.0", "end")
            txt_input.insert("1.0", content)
            lbl_result.configure(text=f"📄 '{os.path.basename(path)}' yüklendi", text_color="green")
    except Exception as e:
        lbl_result.configure(text=f"❌ Dosya okunamadı: {e}", text_color="red")

def drop_file(event):
    paths = app.tk.splitlist(event.data)
    for path in paths:
        load_file(path)

# --- GUI Ayarları ---
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

app = TkinterDnD.Tk()
app.title("🔐 Craftrise Decryptor - Created by atapiro.")
app.geometry("750x650")

# İçerik Frame
frame = ctk.CTkFrame(app, corner_radius=15, fg_color="#111111")
frame.place(relx=0, rely=0, relwidth=1, relheight=1)

lbl_title = ctk.CTkLabel(frame, text="🔓 Craftrise Decryptor", font=("Arial", 26, "bold"))
lbl_title.pack(pady=15)

# Yazılacak yer ve sonuç için kırmızı çerçeve
txt_frame = ctk.CTkFrame(frame, fg_color="#111111", border_width=3, border_color="#ff0000", corner_radius=10)
txt_frame.pack(pady=10, padx=20, fill="both", expand=False)

txt_input = scrolledtext.ScrolledText(txt_frame, width=80, height=12, font=("Consolas", 12, "bold"), bg="#111111", fg="#ffffff", insertbackground="#ff0000", borderwidth=0, highlightthickness=0)
txt_input.pack(padx=5, pady=5, fill="both", expand=True)

# Sürükle-bırak
txt_input.drop_target_register(DND_FILES)
txt_input.dnd_bind('<<Drop>>', drop_file)

frame_btn = ctk.CTkFrame(frame, fg_color="#111111")
frame_btn.pack(pady=15)

btn1 = ctk.CTkButton(frame_btn, text="Config JSON Çöz", command=coz_config, width=200, corner_radius=10, fg_color="#222222", hover_color="#333333")
btn1.grid(row=0, column=0, padx=10)

btn2 = ctk.CTkButton(frame_btn, text="AES Çöz", command=coz_aes, width=200, corner_radius=10, fg_color="#222222", hover_color="#333333")
btn2.grid(row=0, column=1, padx=10)

btn3 = ctk.CTkButton(frame_btn, text="Base64 Çöz", command=coz_base64, width=200, corner_radius=10, fg_color="#222222", hover_color="#333333")
btn3.grid(row=0, column=2, padx=10)

btn_copy = ctk.CTkButton(frame, text="📋 Kopyala", command=copy_result, width=200, corner_radius=10, fg_color="#222222", hover_color="#333333")
btn_copy.pack(pady=10)

lbl_result = ctk.CTkLabel(frame, text="Sonuç burada görünecek...", font=("Arial", 16), wraplength=700, text_color="#ffffff")
lbl_result.pack(pady=10)

lbl_credit = ctk.CTkLabel(frame, text="Created by atapiro.", font=("Arial", 12, "italic"), text_color="#888888")
lbl_credit.pack(side="bottom", pady=5)

app.mainloop()
