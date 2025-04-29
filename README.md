JWT Decoder & Re-signer
A Python-based GUI application for decoding, editing, and re-signing JSON Web Tokens (JWTs). Built with Tkinter and PyJWT, this tool provides a modern, user-friendly interface with a dark theme, supporting HMAC-based algorithms (HS256, HS384, HS512). Ideal for developers and security professionals working with JWT-based authentication systems.
Features

Decode JWTs: View the header and payload of a JWT in a readable, editable format.
Edit JWTs: Modify the header and payload, with JSON validation.
Re-sign JWTs: Generate a new JWT with a provided secret key and selected algorithm.
Signature Verification: Verify the JWT's signature before decoding.
Algorithm Support: Choose from HS256, HS384, or HS512 algorithms.
User-Friendly GUI: Modern dark theme with scrollbars, resizable window, and copy-to-clipboard functionality.
Secure Key Handling: Secret key input is masked for security.
Input Validation: Ensures valid JWT format and JSON content.

Screenshots
Modern dark theme with editable fields and algorithm selection.
Prerequisites

Python 3.6 or higher
Tkinter (usually included with Python)
PyJWT library

Installation

Clone the Repository:
git clone https://github.com/ITEKONGIT/jwt-decoder-resigner.git
cd jwt-decoder-resigner


Create a Virtual Environment (optional but recommended):
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate


Install Dependencies:
pip install -r requirements.txt



Usage

Run the Application:
python jwt_gui.py


Steps:

Enter a JWT token in the "Enter JWT Token" field (e.g., eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c).
Enter the secret key in the "Enter Secret Key" field (e.g., your-256-bit-secret).
Select an algorithm (HS256, HS384, or HS512) from the dropdown.
Click "Decode JWT" to view the header and payload.
Edit the header or payload in the provided text areas.
Click "Re-sign JWT" to generate a new token.
Use "Copy to Clipboard" to copy the re-signed JWT or "Clear All" to reset the fields.


Example:

Input JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
Secret Key: your-256-bit-secret
Algorithm: HS256
Output: Decoded header and payload displayed, editable, and re-signable.



Project Structure
jwt-decoder-resigner/
├── jwt_gui.py          # Main GUI application
├── jwt_utils.py        # JWT handling utilities
├── requirements.txt    # Python dependencies
├── README.md           # Project documentation

Dependencies
Listed in requirements.txt:

pyjwt>=2.8.0

Notes

The application supports HMAC-based algorithms (HS256, HS384, HS512). RSA or ECDSA algorithms require additional configuration (e.g., public/private keys).
Ensure jwt_utils.py is in the same directory as jwt_gui.py.
The GUI is resizable and includes scrollbars for handling large JWTs.

Contributing

Fork the repository.
Create a new branch: git checkout -b feature/your-feature.
Make changes and commit: git commit -m "Add your feature".
Push to the branch: git push origin feature/your-feature.
Open a pull request.

License
This project is licensed under the MIT License. See the LICENSE file for details.
Contact
For issues or suggestions, open an issue on GitHub or contact itek632@proton.me.
