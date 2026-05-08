# Sovereign Guard: Secure System for User Data and Social Posts using RSA/ECC

Sovereign Guard is a CSE447 coursework web application that demonstrates secure registration, login, 2FA, encrypted profile/post storage, HMAC integrity checking, RBAC, key management, and session protection.

## How to run

Open `index.html` directly in a modern browser, or serve the folder locally:

```bash
python -m http.server 8000
# then open http://localhost:8000
```

No backend is required for the classroom demo. The demo database is stored in browser `localStorage` so the encrypted records can be inspected in the **Encrypted Storage** page.

## Demo accounts

- Admin: `admin` / `Admin@12345`
- Regular user: `user` / `User@12345`

After password verification, the current classroom OTP is displayed on screen to demonstrate the second authentication factor.

## Implemented modules

- Login and registration
- RSA encryption for user/profile fields
- ECC/EC-ElGamal encryption for post fields
- Salted password hashing using from-scratch SHA-256
- HMAC-SHA256 integrity verification
- Two-step authentication
- Key generation, sealed key storage, public-key distribution, and rotation
- RBAC for admin vs regular users
- Signed session token with expiry and sessionStorage isolation
- Raw encrypted database evidence page


