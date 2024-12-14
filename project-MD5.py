import math
import tkinter as tk
from tkinter import filedialog, messagebox


def md5_padding(message):
    original_byte_len = len(message)
    original_bit_len = original_byte_len * 8
    message += b'\x80'
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'
    message += original_bit_len.to_bytes(8, byteorder='little')
    return message


def md5_process(message):
    A = 0x67452301
    B = 0xEFCDAB89
    C = 0x98BADCFE
    D = 0x10325476
    chunks = [message[i:i + 64] for i in range(0, len(message), 64)]
    T = [int(2**32 * abs(math.sin(i + 1))) & 0xFFFFFFFF for i in range(64)]

    def left_rotate(x, c):
        return ((x << c) | (x >> (32 - c))) & 0xFFFFFFFF

    def F(X, Y, Z): return (X & Y) | (~X & Z)
    def G(X, Y, Z): return (X & Z) | (Y & ~Z)
    def H(X, Y, Z): return X ^ Y ^ Z
    def I(X, Y, Z): return Y ^ (X | ~Z)

    rotation = [
        7, 12, 17, 22,
        5,  9, 14, 20,
        4, 11, 16, 23,
        6, 10, 15, 21
    ] * 4

    for chunk in chunks:
        M = [int.from_bytes(chunk[i:i + 4], byteorder='little') for i in range(0, 64, 4)]
        AA, BB, CC, DD = A, B, C, D
        for i in range(64):
            if i < 16:
                F_i = F(B, C, D)
                g = i
            elif i < 32:
                F_i = G(B, C, D)
                g = (5 * i + 1) % 16
            elif i < 48:
                F_i = H(B, C, D)
                g = (3 * i + 5) % 16
            else:
                F_i = I(B, C, D)
                g = (7 * i) % 16
            temp = (A + F_i + M[g] + T[i]) & 0xFFFFFFFF
            temp = (B + left_rotate(temp, rotation[(i // 16) * 4 + (i % 4)])) & 0xFFFFFFFF
            A, D, C, B = D, C, B, temp
        A = (A + AA) & 0xFFFFFFFF
        B = (B + BB) & 0xFFFFFFFF
        C = (C + CC) & 0xFFFFFFFF
        D = (D + DD) & 0xFFFFFFFF
    result = sum(x << (32 * i) for i, x in enumerate([A, B, C, D]))
    return result.to_bytes(16, byteorder='little').hex()


def hash_text():
    text = text_entry.get().encode('utf-8')
    padded = md5_padding(text)
    hash_val = md5_process(padded)
    result_var.set(f"MD5: {hash_val}")


def hash_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        with open(file_path, 'rb') as file:
            content = file.read()
            padded = md5_padding(content)
            hash_val = md5_process(padded)
            result_var.set(f"MD5: {hash_val}")
    else:
        messagebox.showwarning("No file", "No file selected.")


root = tk.Tk()
root.title("MD5 Hash Generator")

frame = tk.Frame(root, padx=10, pady=10)
frame.pack()

tk.Label(frame, text="Enter text:").grid(row=0, column=0, sticky='e')
text_entry = tk.Entry(frame, width=50)
text_entry.grid(row=0, column=1, pady=5)

hash_text_btn = tk.Button(frame, text="Hash Text", command=hash_text)
hash_text_btn.grid(row=1, column=0, columnspan=2, pady=5)

separator = tk.Label(frame, text="or")
separator.grid(row=2, column=0, columnspan=2)

hash_file_btn = tk.Button(frame, text="Hash File", command=hash_file)
hash_file_btn.grid(row=3, column=0, columnspan=2, pady=5)

result_var = tk.StringVar()
tk.Label(frame, textvariable=result_var).grid(row=4, column=0, columnspan=2, pady=10)

root.mainloop()
'''
This program creates a simple GUI that allows the user to input text or select a file to calculate the MD5 hash. The `md5_padding` function is used to pad the message to a multiple of 512 bits, and the `md5_process` function calculates the MD5 hash of the padded message. The `hash_text` and `hash_file` functions handle the input from the user and display the resulting MD5 hash. The program uses the `tkinter` library for the GUI components
To run the program, save the code to a file named `project-MD5.py` and run it using a Python interpreter. The program will display a window where the user can input text or select a file to calculate the MD5 hash. The resulting hash will be displayed in the window.
Note: The MD5 algorithm is considered insecure and should not be used for cryptographic purposes. It is included here for educational purposes only.
'''