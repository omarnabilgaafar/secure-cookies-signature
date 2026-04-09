# 🔐 Secure Cookies & Digital Signature System

## 📌 Overview

This project demonstrates key concepts in **Data Integrity and Authentication**, including:

* Secure cookie protection using **HMAC (SHA-256)**
* Digital signatures using **RSA**
* Detection of tampering and attack scenarios
* Demonstration of a **Key Substitution Attack (Bonus)**

---

## 🚀 Features

### 🧩 Part A: Secure Cookies with MAC

* User login system
* Cookie contains:

  * Username
  * Role
  * Expiration timestamp
* Cookie is protected using **HMAC-SHA256**
* Server verifies integrity on every request
* Any tampering is detected and rejected

---

### 🔐 Part B: Digital Signature (RSA)

* RSA key pair generation (Public & Private keys)
* File signing using private key
* Signature verification using public key
* Detects file modification after signing

---

### 💣 Bonus: Key Substitution Attack

* Demonstrates how an attacker can:

  * Replace the public key
  * Sign fake data
* Shows that verification can incorrectly succeed
* Highlights importance of trusted key distribution (PKI)

---

## 🛠️ Technologies Used

* Python 🐍
* Flask 🌐
* Cryptography Library 🔐

---

## 📂 Project Structure

```
project/
│── app.py
│── uploads/
│── signatures/
│── keys/
```

---

## ⚙️ Installation

```bash
pip install flask cryptography
```

---

## ▶️ Run the Application

```bash
python app.py
```

Server runs at:

```
http://127.0.0.1:5000
```

---

## 📡 API Endpoints

### 🔑 Authentication

* `POST /login`
* `GET /protected`

### 🔐 Digital Signature

* `POST /generate-keys`
* `POST /sign-file`
* `POST /verify-file`

### 💣 Bonus Attack

* `POST /attack/key-substitution`

---

## 🧪 Demonstration Steps

### Part A

1. Login successfully
2. Access protected route
3. Modify cookie manually
4. Request is rejected

---

### Part B

1. Generate RSA keys
2. Sign a file
3. Verify original file → ✅ Success
4. Modify file
5. Verify again → ❌ Failed

---

### Bonus

* Run key substitution attack
* Observe verification succeeds incorrectly

---

## 🔒 Security Concepts

* **Integrity** → Data cannot be modified undetected
* **Authentication** → Verifying identity of sender
* **HMAC** → Protects cookie from tampering
* **Digital Signature** → Ensures integrity + authenticity

---

## ⚠️ Important Notes

* Secret key is stored only on the server
* Public key must be trusted to avoid attacks
* This project is for educational purposes only

---

## 👨‍💻 Author

* Omar Nabil

---

## 📚 Course

Data Integrity and Authentication
