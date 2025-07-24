# SecureEncryptor

SecureEncryptor, dosya ve klasörlerinizi şifreleyip korumanızı sağlayan basit ve kullanışlı bir Python uygulamasıdır.  
Google Drive entegrasyonu sayesinde, şifre yanlış girildiğinde dosyanız otomatik olarak buluta yüklenip yerelden silinir.

---

## Özellikler

- Dosya ve klasör şifreleme
- Klasörleri ZIP formatında sıkıştırarak şifreleme
- Şifre çözme (otomatik olarak dosya mı yoksa klasör mü olduğunu algılar)
- 5 kez hatalı şifre girişinde dosyayı Google Drive’a yükleme ve yerelden silme
- Basit ve kullanıcı dostu Tkinter GUI arayüzü

---

## Gereksinimler

- Python 3.7 ve üzeri
- Aşağıdaki kütüphaneler:

```bash
pip install cryptography google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client
```
## Kurulum ve Kullanım
Bu depoyu klonlayın veya ZIP olarak indirip açın.

### Google Drive API kullanımı için:

console.cloud.google.com üzerinden OAuth 2.0 istemci kimlik bilgilerinizi oluşturun.

credentials.json dosyasını proje dizinine koyun.

### Terminal veya komut istemcisinden programı çalıştırın:
```bash
python secure_encryptor.py
```
Açılan arayüzden dosya veya klasör seçip şifreleyebilir ya da şifresini çözebilirsiniz.

## Önemli Notlar
Klasörler ZIP formatında sıkıştırılıp şifrelenir.

Şifre çözme işlemi, şifrelenen nesnenin dosya mı yoksa klasör mü olduğunu otomatik algılar.

Yanlış şifre 5 kez girilirse dosya Google Drive'a yüklenecek ve yerelden silinecektir.

wrong_attempts.txt dosyası şifre yanlış denemelerini takip eder.
