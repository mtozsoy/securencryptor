import os
import hashlib
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
from urllib.request import Request
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import zipfile
import tempfile
import shutil

WRONG_ATTEMPTS_FILE = "wrong_attempts.txt"
SCOPES = ['https://www.googleapis.com/auth/drive.file']

def generate_key(password, salt=b'static_salt'):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return urlsafe_b64encode(kdf.derive(password.encode()))

def create_zip_from_folder(folder_path, zip_path):
    """Klasörü ZIP dosyası olarak sıkıştırır"""
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, folder_path)
                zipf.write(file_path, arcname)

def extract_zip_to_folder(zip_path, extract_path):
    """ZIP dosyasını belirtilen klasöre çıkarır"""
    with zipfile.ZipFile(zip_path, 'r') as zipf:
        zipf.extractall(extract_path)

def encrypt_file(filepath, password):
    key = generate_key(password)
    fernet = Fernet(key)

    with open(filepath, 'rb') as file:
        data = file.read()

    encrypted = fernet.encrypt(data)
    new_path = filepath + '.enc'

    with open(new_path, 'wb') as enc_file:
        enc_file.write(encrypted)

    os.remove(filepath)
    messagebox.showinfo("Başarılı", f"Şifreleme tamamlandı: {new_path}")

def encrypt_folder(folder_path, password):
    """Klasörü ZIP'leyip şifreler"""
    key = generate_key(password)
    fernet = Fernet(key)
    
    # Geçici ZIP dosyası oluştur
    temp_dir = tempfile.gettempdir()
    folder_name = os.path.basename(folder_path.rstrip('/\\'))
    temp_zip_path = os.path.join(temp_dir, f"{folder_name}_temp.zip")
    
    try:
        # Klasörü ZIP'le
        create_zip_from_folder(folder_path, temp_zip_path)
        
        # ZIP dosyasını oku ve şifrele
        with open(temp_zip_path, 'rb') as file:
            data = file.read()
        
        encrypted = fernet.encrypt(data)
        
        # Şifrelenmiş dosyayı kaydet
        encrypted_path = folder_path + '.enc'
        with open(encrypted_path, 'wb') as enc_file:
            enc_file.write(encrypted)
        
        # Orijinal klasörü ve geçici ZIP'i sil
        shutil.rmtree(folder_path)
        os.remove(temp_zip_path)
        
        messagebox.showinfo("Başarılı", f"Klasör şifrelemesi tamamlandı: {encrypted_path}")
        
    except Exception as e:
        # Hata durumunda geçici dosyayı temizle
        if os.path.exists(temp_zip_path):
            os.remove(temp_zip_path)
        messagebox.showerror("Hata", f"Klasör şifrelenirken hata oluştu: {str(e)}")

def decrypt_file(filepath, password):
    key = generate_key(password)
    fernet = Fernet(key)

    try:
        with open(filepath, 'rb') as file:
            encrypted = file.read()
        decrypted = fernet.decrypt(encrypted)
    except Exception:
        log_wrong_attempt(filepath)
        raise ValueError("Şifre yanlış!")

    # Orijinal uzantıyı bul
    original_path = filepath.replace('.enc', '')
    
    # Eğer orijinal bir klasör ise, ZIP olarak çıkar ve klasöre dönüştür
    if os.path.isdir(original_path + '_backup') or not os.path.splitext(original_path)[1]:
        # Bu muhtemelen bir klasördü, ZIP olarak çıkar
        temp_dir = tempfile.gettempdir()
        temp_zip_path = os.path.join(temp_dir, "temp_decrypt.zip")
        
        try:
            # Şifresi çözülmüş veriyi geçici ZIP dosyası olarak kaydet
            with open(temp_zip_path, 'wb') as temp_file:
                temp_file.write(decrypted)
            
            # ZIP'i çıkar
            extract_zip_to_folder(temp_zip_path, original_path)
            
            # Geçici ZIP'i temizle
            os.remove(temp_zip_path)
            
            messagebox.showinfo("Başarılı", f"Klasör şifre çözme tamamlandı: {original_path}")
            
        except zipfile.BadZipFile:
            # ZIP dosyası değilse normal dosya olarak kaydet
            with open(original_path, 'wb') as dec_file:
                dec_file.write(decrypted)
            messagebox.showinfo("Başarılı", f"Dosya şifre çözme tamamlandı: {original_path}")
        except Exception as e:
            if os.path.exists(temp_zip_path):
                os.remove(temp_zip_path)
            raise e
    else:
        # Normal dosya
        with open(original_path, 'wb') as dec_file:
            dec_file.write(decrypted)
        messagebox.showinfo("Başarılı", f"Dosya şifre çözme tamamlandı: {original_path}")

    os.remove(filepath)
    clear_wrong_attempts(filepath)

def log_wrong_attempt(filepath):
    # Dosya yoksa oluştur
    if not os.path.exists(WRONG_ATTEMPTS_FILE):
        open(WRONG_ATTEMPTS_FILE, 'w').close()
    
    # Mevcut kayıtları oku
    with open(WRONG_ATTEMPTS_FILE, 'r') as f:
        lines = f.readlines()
    
    count = 0
    new_lines = []
    found = False
    
    # Mevcut kayıtları kontrol et
    for line in lines:
        if line.strip() and filepath in line.split(',')[0]:
            # Bu dosya için kayıt var, sayacı artır
            count = int(line.split(',')[1].strip()) + 1
            new_lines.append(f"{filepath},{count}\n")
            found = True
        else:
            # Diğer kayıtları koru
            new_lines.append(line)
    
    # Eğer dosya için kayıt yoksa yeni kayıt ekle
    if not found:
        count = 1
        new_lines.append(f"{filepath},{count}\n")
    
    # Dosyayı güncelle
    with open(WRONG_ATTEMPTS_FILE, 'w') as f:
        f.writelines(new_lines)

    if count >= 5:
        messagebox.showwarning("UYARI", f"Şifre 5 kez yanlış girildi! Dosya Drive'a yüklenecek ve yerelden silinecek.")
        
        # Drive'a yüklemeyi dene
        upload_success = upload_to_drive(filepath)
        
        if upload_success:
            try:
                os.remove(filepath)
                clear_wrong_attempts(filepath)
                messagebox.showinfo("Tamamlandı", "Dosya başarıyla Drive'a yüklendi ve yerelden silindi.")
            except Exception as e:
                messagebox.showerror("Dosya Silme Hatası", f"Dosya Drive'a yüklendi ancak yerelden silinirken hata oluştu:\n{str(e)}")
        else:
            messagebox.showerror("Yükleme Başarısız", "Dosya Drive'a yüklenemedi. Dosya yerelde korunuyor.")
    else:
        messagebox.showerror("Yanlış Şifre", f"Şifre yanlış! Kalan deneme hakkı: {5-count}")

def clear_wrong_attempts(filepath):
    """Belirtilen dosya için yanlış deneme kayıtlarını temizler"""
    if not os.path.exists(WRONG_ATTEMPTS_FILE):
        return
    
    with open(WRONG_ATTEMPTS_FILE, 'r') as f:
        lines = f.readlines()
    
    # Belirtilen dosya dışındaki kayıtları koru
    new_lines = [line for line in lines if not line.startswith(filepath + ',')]
    
    with open(WRONG_ATTEMPTS_FILE, 'w') as f:
        f.writelines(new_lines)

def upload_to_drive(filepath):
    """Dosyayı Google Drive'a yükler"""
    try:
        # Gerekli dosyaları kontrol et
        if not os.path.exists('credentials.json'):
            messagebox.showerror("Hata", "Google Drive API için 'credentials.json' dosyası bulunamadı!\n\nLütfen Google Cloud Console'dan OAuth 2.0 kimlik bilgilerini indirin.")
            return False
        
        creds = None
        if os.path.exists('token.json'):
            try:
                creds = Credentials.from_authorized_user_file('token.json', SCOPES)
            except Exception as e:
                print(f"Token dosyası okuma hatası: {e}")
                # Bozuk token dosyasını sil
                os.remove('token.json')

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                except Exception as e:
                    print(f"Token yenileme hatası: {e}")
                    # Bozuk token'ı sil ve yeniden yetkilendirme yap
                    if os.path.exists('token.json'):
                        os.remove('token.json')
                    creds = None
            
            if not creds:
                try:
                    flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
                    creds = flow.run_local_server(port=0)
                except Exception as e:
                    messagebox.showerror("Yetkilendirme Hatası", f"Google Drive yetkilendirme hatası:\n{str(e)}\n\nLütfen 'credentials.json' dosyasının doğru olduğundan emin olun.")
                    return False
            
            # Token'ı kaydet
            try:
                with open('token.json', 'w') as token:
                    token.write(creds.to_json())
            except Exception as e:
                print(f"Token kaydetme hatası: {e}")

        # Drive servisi oluştur
        try:
            service = build('drive', 'v3', credentials=creds)
        except Exception as e:
            messagebox.showerror("Servis Hatası", f"Google Drive servisi oluşturulamadı:\n{str(e)}")
            return False

        # Dosyayı yükle
        try:
            from googleapiclient.http import MediaFileUpload
            
            file_metadata = {'name': os.path.basename(filepath)}
            media = MediaFileUpload(filepath, resumable=True)
            
            file = service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id'
            ).execute()
            
            print(f"Dosya Drive'a yüklendi. File ID: {file.get('id')}")
            return True
            
        except Exception as e:
            messagebox.showerror("Yükleme Hatası", f"Dosya Drive'a yüklenirken hata oluştu:\n{str(e)}")
            return False
            
    except Exception as e:
        messagebox.showerror("Genel Hata", f"Drive yükleme işleminde beklenmeyen hata:\n{str(e)}")
        return False

def select_file_encrypt():
    filepath = filedialog.askopenfilename()
    if filepath:
        password = simpledialog.askstring("Şifre", "Lütfen bir şifre girin:", show="*")
        if password:
            encrypt_file(filepath, password)

def select_folder_encrypt():
    """Klasör seçip şifreler"""
    folder_path = filedialog.askdirectory()
    if folder_path:
        password = simpledialog.askstring("Şifre", "Lütfen bir şifre girin:", show="*")
        if password:
            encrypt_folder(folder_path, password)

def select_file_decrypt():
    filepath = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
    if filepath:
        password = simpledialog.askstring("Şifre", "Lütfen şifreyi girin:", show="*")
        if password:
            try:
                decrypt_file(filepath, password)
            except ValueError as e:
                messagebox.showerror("Hata", str(e))

def build_gui():
    root = tk.Tk()
    root.title("SecureEncryptor - Dosya & Klasör Şifreleme")
    root.geometry("450x300")

    tk.Label(root, text="Hoş geldin!", font=("Helvetica", 16)).pack(pady=10)
    
    # Şifreleme bölümü
    tk.Label(root, text="Şifreleme:", font=("Helvetica", 12, "bold")).pack(pady=(20, 5))
    tk.Button(root, text="Dosya Şifrele", command=select_file_encrypt, width=30, bg="#4CAF50", fg="white").pack(pady=5)
    tk.Button(root, text="Klasör Şifrele", command=select_folder_encrypt, width=30, bg="#2196F3", fg="white").pack(pady=5)
    
    # Şifre çözme bölümü
    tk.Label(root, text="Şifre Çözme:", font=("Helvetica", 12, "bold")).pack(pady=(20, 5))
    tk.Button(root, text="Şifre Çöz (.enc dosyası)", command=select_file_decrypt, width=30, bg="#FF9800", fg="white").pack(pady=5)
    
    # Bilgi etiketi
    info_text = "Not: Klasörler ZIP formatında sıkıştırılıp şifrelenir.\nŞifre çözme işlemi otomatik olarak klasör/dosya formatını algılar."
    tk.Label(root, text=info_text, font=("Helvetica", 9), fg="gray", wraplength=400, justify="center").pack(pady=20)

    root.mainloop()

if __name__ == "__main__":
    # Google API kütüphanelerini kontrol et
    try:
        from googleapiclient.http import MediaFileUpload
        print("Google API kütüphaneleri yüklendi.")
    except ImportError as e:
        print(f"Google API kütüphaneleri eksik: {e}")
        print("Lütfen şu komutları çalıştırın:")
        print("pip install google-auth google-auth-oauthlib google-auth-httplib2")
        print("pip install google-api-python-client")
    
    build_gui()