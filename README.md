# Secure-File-Encryption-and-Decryption-System
🔐 Secure File Encryption & Decryption System

A desktop application built using Python and Tkinter that allows users to securely encrypt and decrypt files using strong cryptographic algorithms.

📌 Features

Encrypt any type of file (text, images, PDFs, etc.)

Decrypt files only with the correct password

Image preview before encryption

User-friendly graphical interface (GUI)

Uses strong encryption standards (AES via Fernet)

🛠️ Technologies Used

Programming Language: Python 3

GUI Framework: Tkinter

Cryptography Library: cryptography

Image Handling: Pillow (PIL)

🔧 Installation
1. Clone or Download the Project

Download the project folder or clone it if using Git.

2. Install Required Libraries

Open Command Prompt / Terminal in the project folder and run:

pip install cryptography pillow

▶️ How to Run the Project

In the project directory, run:

python app.py


The application window will open.

🧪 How to Use
🔐 Encrypt a File

Enter a password.

Click Encrypt File.

Select the file you want to encrypt.

Encrypted file will be saved with .enc extension.

🔓 Decrypt a File

Enter the same password used during encryption.

Click Decrypt File.

Select the encrypted .enc file.

Original file will be restored.

🖼️ Preview Image

Click Preview Image to view an image before encryption.

🧠 Cryptography Concepts Used

AES (Advanced Encryption Standard)

PBKDF2 (Password-Based Key Derivation Function)

Salt for secure key generation

📁 Project Structure
SecureFileEncryptor/
│
├── app.py
└── README.md

🔐 Security Note

Do not forget your password.

Encrypted files cannot be recovered without the correct password
