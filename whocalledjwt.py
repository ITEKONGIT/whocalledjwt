import tkinter as tk
from tkinter import messagebox, ttk
import json
import jwt
import re
from jwt_utils import decode_jwt, encode_jwt, verify_jwt

# Constants for styling
BG_COLOR = "#1e1e2e"
FG_COLOR = "#00ff88"
ACCENT_COLOR = "#3b82f6"
BUTTON_BG = "#2a2a3a"
BUTTON_HOVER = "#3a3a4a"
FONT = ("Consolas", 10)
PADX = 10
PADY = 5

class JWTApp:
    def __init__(self, root):
        self.root = root
        self.root.title("JWT Decoder & Re-signer")
        self.root.geometry("800x700")
        self.root.resizable(True, True)
        self.root.configure(bg=BG_COLOR)

        # Main frame with gradient background
        self.main_frame = tk.Frame(root, bg=BG_COLOR)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Styling for widgets
        self.style = ttk.Style()
        self.style.configure("TButton", font=FONT, padding=5)
        self.style.configure("TCombobox", font=FONT)

        self.setup_gui()
        self.algorithm = "HS256"  # Default algorithm

    def create_hacker_widget(self, widget_type, parent, **kwargs):
        """Create a styled widget with hacker theme."""
        widget = widget_type(parent, **kwargs)
        if isinstance(widget, (tk.Text, tk.Entry)):
            widget.config(bg=BUTTON_BG, fg=FG_COLOR, font=FONT, insertbackground=FG_COLOR)
        elif isinstance(widget, tk.Button):
            widget.config(bg=BUTTON_BG, fg=FG_COLOR, font=FONT, activebackground=BUTTON_HOVER, relief="flat")
            widget.bind("<Enter>", lambda e: widget.config(bg=BUTTON_HOVER))
            widget.bind("<Leave>", lambda e: widget.config(bg=BUTTON_BG))
        return widget

    def setup_gui(self):
        """Set up the GUI layout."""
        # JWT Input
        tk.Label(self.main_frame, text="Enter JWT Token:", bg=BG_COLOR, fg=FG_COLOR, font=FONT).pack(pady=PADY)
        self.jwt_input = self.create_hacker_widget(tk.Text, self.main_frame, height=4, width=80, wrap=tk.WORD)
        self.jwt_input.pack(pady=PADY)
        self.jwt_scroll = tk.Scrollbar(self.main_frame, orient=tk.VERTICAL, command=self.jwt_input.yview)
        self.jwt_input.config(yscrollcommand=self.jwt_scroll.set)
        self.jwt_scroll.pack(side=tk.RIGHT, fill=tk.Y, before=self.jwt_input)

        # Secret Key Input
        tk.Label(self.main_frame, text="Enter Secret Key:", bg=BG_COLOR, fg=FG_COLOR, font=FONT).pack(pady=PADY)
        self.secret_input = self.create_hacker_widget(tk.Entry, self.main_frame, width=80, show="*")
        self.secret_input.pack(pady=PADY)

        # Algorithm Selection
        tk.Label(self.main_frame, text="Select Algorithm:", bg=BG_COLOR, fg=FG_COLOR, font=FONT).pack(pady=PADY)
        self.algo_var = tk.StringVar(value="HS256")
        self.algo_menu = ttk.Combobox(self.main_frame, textvariable=self.algo_var, values=["HS256", "HS384", "HS512"], state="readonly", width=10)
        self.algo_menu.config(font=FONT)
        self.algo_menu.pack(pady=PADY)

        # Button Frame
        button_frame = tk.Frame(self.main_frame, bg=BG_COLOR)
        button_frame.pack(pady=10)

        # Decode Button
        self.decode_button = self.create_hacker_widget(tk.Button, button_frame, text="Decode JWT", width=15, command=self.manipulate_jwt)
        self.decode_button.pack(side=tk.LEFT, padx=5)

        # Clear Button
        self.clear_button = self.create_hacker_widget(tk.Button, button_frame, text="Clear All", width=15, command=self.clear_all)
        self.clear_button.pack(side=tk.LEFT, padx=5)

        # Header Input
        tk.Label(self.main_frame, text="Decoded JWT Header (Editable):", bg=BG_COLOR, fg=FG_COLOR, font=FONT).pack(pady=PADY)
        self.header_text = self.create_hacker_widget(tk.Text, self.main_frame, height=6, width=80, wrap=tk.WORD)
        self.header_text.pack(pady=PADY)
        self.header_scroll = tk.Scrollbar(self.main_frame, orient=tk.VERTICAL, command=self.header_text.yview)
        self.header_text.config(yscrollcommand=self.header_scroll.set)
        self.header_scroll.pack(side=tk.RIGHT, fill=tk.Y, before=self.header_text)

        # Payload Input
        tk.Label(self.main_frame, text="Decoded JWT Payload (Editable):", bg=BG_COLOR, fg=FG_COLOR, font=FONT).pack(pady=PADY)
        self.payload_text = self.create_hacker_widget(tk.Text, self.main_frame, height=6, width=80, wrap=tk.WORD)
        self.payload_text.pack(pady=PADY)
        self.payload_scroll = tk.Scrollbar(self.main_frame, orient=tk.VERTICAL, command=self.payload_text.yview)
        self.payload_text.config(yscrollcommand=self.payload_scroll.set)
        self.payload_scroll.pack(side=tk.RIGHT, fill=tk.Y, before=self.payload_text)

        # Re-sign Button
        self.resign_button = self.create_hacker_widget(tk.Button, self.main_frame, text="Re-sign JWT", width=15, state=tk.DISABLED, command=self.resign_jwt)
        self.resign_button.pack(pady=10)

        # Result Output
        tk.Label(self.main_frame, text="Re-signed JWT (Result):", bg=BG_COLOR, fg=FG_COLOR, font=FONT).pack(pady=PADY)
        self.result_text = self.create_hacker_widget(tk.Text, self.main_frame, height=4, width=80, wrap=tk.WORD)
        self.result_text.pack(pady=PADY)
        self.result_scroll = tk.Scrollbar(self.main_frame, orient=tk.VERTICAL, command=self.result_text.yview)
        self.result_text.config(yscrollcommand=self.result_scroll.set)
        self.result_scroll.pack(side=tk.RIGHT, fill=tk.Y, before=self.result_text)

        # Copy Button
        self.copy_button = self.create_hacker_widget(tk.Button, self.main_frame, text="Copy to Clipboard", width=15, command=self.copy_to_clipboard)
        self.copy_button.pack(pady=5)

    def is_valid_jwt(self, token):
        """Validate JWT format."""
        return bool(re.match(r'^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$', token))

    def is_valid_json(self, text):
        """Check if text is valid JSON."""
        try:
            json.loads(text)
            return True
        except json.JSONDecodeError:
            return False

    def manipulate_jwt(self):
        """Decode JWT and populate header/payload fields."""
        jwt_token = self.jwt_input.get("1.0", "end-1c").strip()
        secret_key = self.secret_input.get().strip()
        self.algorithm = self.algo_var.get()

        if not jwt_token or not secret_key:
            messagebox.showerror("Error", "JWT Token and Secret Key are required.")
            return
        if not self.is_valid_jwt(jwt_token):
            messagebox.showerror("Error", "Invalid JWT format: Must have three parts separated by dots.")
            return

        if not verify_jwt(jwt_token, secret_key, self.algorithm):
            messagebox.showwarning("Warning", "JWT signature verification failed.")

        header, payload = decode_jwt(jwt_token)
        if not header or not payload:
            return

        self.header_text.delete("1.0", "end")
        self.payload_text.delete("1.0", "end")
        self.header_text.insert("1.0", json.dumps(header, indent=4))
        self.payload_text.insert("1.0", json.dumps(payload, indent=4))
        self.resign_button.config(state=tk.NORMAL)
        messagebox.showinfo("Success", "JWT decoded successfully!")

    def resign_jwt(self):
        """Re-sign JWT with edited header/payload."""
        secret_key = self.secret_input.get().strip()
        header_text = self.header_text.get("1.0", "end-1c").strip()
        payload_text = self.payload_text.get("1.0", "end-1c").strip()
        self.algorithm = self.algo_var.get()

        if not self.is_valid_json(header_text):
            messagebox.showerror("Error", "Invalid JSON in header.")
            return
        if not self.is_valid_json(payload_text):
            messagebox.showerror("Error", "Invalid JSON in payload.")
            return

        header = json.loads(header_text)
        payload = json.loads(payload_text)
        header["alg"] = self.algorithm  # Update algorithm in header

        signed_jwt = encode_jwt(header, payload, secret_key, self.algorithm)
        if signed_jwt:
            self.result_text.delete("1.0", "end")
            self.result_text.insert("1.0", signed_jwt)
            messagebox.showinfo("Success", "JWT re-signed successfully!")

    def copy_to_clipboard(self):
        """Copy re-signed JWT to clipboard."""
        result = self.result_text.get("1.0", "end-1c").strip()
        if result:
            self.root.clipboard_clear()
            self.root.clipboard_append(result)
            messagebox.showinfo("Success", "Re-signed JWT copied to clipboard!")
        else:
            messagebox.showerror("Error", "No JWT to copy.")

    def clear_all(self):
        """Clear all input and output fields."""
        self.jwt_input.delete("1.0", "end")
        self.secret_input.delete(0, "end")
        self.header_text.delete("1.0", "end")
        self.payload_text.delete("1.0", "end")
        self.result_text.delete("1.0", "end")
        self.resign_button.config(state=tk.DISABLED)
        self.algo_var.set("HS256")

if __name__ == "__main__":
    root = tk.Tk()
    app = JWTApp(root)
    root.mainloop()