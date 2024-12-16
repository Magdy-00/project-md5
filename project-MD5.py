import math
import tkinter as tk
from tkinter import filedialog, messagebox

#Increases the length of the message to a multiple of 512 bits
def md5_padding(message):
    original_byte_len = len(message)
    original_bit_len = original_byte_len * 8
    message += b'\x80' #padding b-> byte  10000000

    while (len(message) * 8) % 512 != 448:
        message += b'\x00' #padding b-> byte  00000000

    #Append the original message length (in bits) as an 8-byte Little Endian value بنحطها في اخر الرسالة
    message += original_bit_len.to_bytes(8, byteorder='little') 
    return message


def md5_process(message):
    # Initialize constants (Registers)
    A = 0x67452301
    B = 0xEFCDAB89
    C = 0x98BADCFE
    D = 0x10325476

    # Break the message into 512-bit chunks, that loops over from 0 to length and adds 64 each time
    chunks = [message[i:i + 64] for i in range(0, len(message), 64)]  #slice the message into 64-byte chunks (512 bits)

    # Precompute T table
    T = [int(2**32 * abs(math.sin(i + 1))) & 0xFFFFFFFF for i in range(64)]

    def left_rotate(x, c):
        # shift left x left by c bits (Left Shift (<<)) (Right Shift (>>))
        return ((x << c) | (x >> (32 - c))) & 0xFFFFFFFF

    def F(X, Y, Z): return (X & Y) | (~X & Z) #X AND Y OR NOT X AND Z
    def G(X, Y, Z): return (X & Z) | (Y & ~Z) #X AND Z OR Y AND NOT Z
    def H(X, Y, Z): return X ^ Y ^ Z          #X XOR Y XOR Z
    def I(X, Y, Z): return Y ^ (X | ~Z)       #Y XOR (X OR NOT Z)

#The list is being repeated to provide rotation values for all 64 rounds of the MD5 algorithm
    rotation = [
        7, 12, 17, 22,
        5, 9, 14, 20,
        4, 11, 16, 23,
        6, 10, 15, 21
    ] * 4


    for chunk in chunks:
        M = [int.from_bytes(chunk[i:i + 4], byteorder='little') for i in range(0, 64, 4)] #converts the binary to intgeres

        AA, BB, CC, DD = A, B, C, D #Save the current values of the registers
        for i in range(64):

            if i < 16:
                F_i = F(B, C, D) #X AND Y OR NOT X AND Z
                g = i # represents the index of the current message block (or the 16 words in the message block)

            elif i < 32:
                F_i = G(B, C, D) #X AND Z OR Y AND NOT Z
                g = (5 * i + 1) % 16

            elif i < 48:
                F_i = H(B, C, D) #X XOR Y XOR Z
                g = (3 * i + 5) % 16

            else:
                F_i = I(B, C, D) #Y XOR (X OR NOT Z)
                g = (7 * i) % 16

                                            #This operation ensures that the result fits within a 32-bit integer
            temp = (A + F_i + M[g] + T[i]) & 0xFFFFFFFF
            temp = (B + left_rotate(temp, rotation[(i // 16) * 4 + (i % 4)])) & 0xFFFFFFFF #Left Shift (<<)
            A, D, C, B = D, C, B, temp #Swap the values of the registers

        A = (A + AA) & 0xFFFFFFFF #This operation ensures that the result stays within 32 bits adds A=(to AA)
        B = (B + BB) & 0xFFFFFFFF #This operation ensures that the result stays within 32 bits adds B=(to BB)
        C = (C + CC) & 0xFFFFFFFF #This operation ensures that the result stays within 32 bits adds C=(to CC)
        D = (D + DD) & 0xFFFFFFFF #This operation ensures that the result stays within 32 bits adds D=(to DD)

    result = sum(x << (32 * i) for i, x in enumerate([A, B, C, D])) #The result is a 128-bit number, which is the final hash value
    return result.to_bytes(16, byteorder='little').hex() # convert the result to a 16-byte Little Endian value and return it as a hexadecimal string


#
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
root.title("MD5 Hash Generator") #Title of the window

frame = tk.Frame(root, padx=10, pady=10) #The frame of the window
frame.pack() #is a method used to add a widge

tk.Label(frame, text="Enter text:").grid(row=0, column=0, sticky='e') #sticky parameter controls where the widget should be "stuck" inside its grid cell
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


"""
T array values
T = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
    0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
    0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
    0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0x8e1b6f8e, 0x677f1c7d, 0xfadf9f1b,
    0x7d71e3b5, 0x03e5c8a1, 0x9b88e3b4, 0x7fa68e1b, 0xf27424e7, 0x8cda79b9,
    0x69e8fcd1, 0xc2b2f1be, 0x0e80b574, 0xa82f8f62, 0x5ab45c4d, 0xb8a7f80f,
]

rotation = [
    7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21,
    7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21,
    7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21,
    7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21
]
"""