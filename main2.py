from tkinter import *
from tkinter import ttk, messagebox
import base64
import time


# Function to encode
def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


# Function to decode
def decode(key, enc):
    try:
        enc = base64.urlsafe_b64decode(enc).decode()
        dec = []
        for i in range(len(enc)):
            key_c = key[i % len(key)]
            dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
            dec.append(dec_c)
        return "".join(dec)
    except Exception as e:
        return "Invalid Key or Message!"


# Main GUI Window
root = Tk()
root.title("Advanced Message Encryption and Decryption")
root.geometry("600x500")
root.configure(bg="lightblue")

# Header Label
header = Label(root, text="Message Encryptor & Decryptor", font=("Arial", 20, "bold"), bg="lightblue")
header.pack(pady=10)

# Input Frame
frame = Frame(root, bg="lightblue")
frame.pack(pady=10)

Label(frame, text="Enter Message:", font=("Arial", 12, "bold"), bg="lightblue").grid(row=0, column=0, sticky=W)
msg_entry = Entry(frame, font=("Arial", 12), width=40)
msg_entry.grid(row=0, column=1, padx=10, pady=5)

Label(frame, text="Enter Key:", font=("Arial", 12, "bold"), bg="lightblue").grid(row=1, column=0, sticky=W)
key_entry = Entry(frame, font=("Arial", 12), width=40, show="*")
key_entry.grid(row=1, column=1, padx=10, pady=5)

Label(frame, text="Mode (E/D):", font=("Arial", 12, "bold"), bg="lightblue").grid(row=2, column=0, sticky=W)
mode_entry = Entry(frame, font=("Arial", 12), width=10)
mode_entry.grid(row=2, column=1, padx=10, pady=5, sticky=W)

# Output Frame
output_frame = Frame(root, bg="lightblue")
output_frame.pack(pady=10)

Label(output_frame, text="Result:", font=("Arial", 12, "bold"), bg="lightblue").grid(row=0, column=0, sticky=W)
result_var = StringVar()
result_entry = Entry(output_frame, font=("Arial", 12), width=40, textvariable=result_var, state="readonly")
result_entry.grid(row=0, column=1, padx=10, pady=5)


# Function to Encrypt/Decrypt
def process_message():
    msg = msg_entry.get()
    key = key_entry.get()
    mode = mode_entry.get().upper()

    if not msg or not key or not mode:
        messagebox.showerror("Error", "All fields are required!")
        return

    if mode == "E":
        result_var.set(encode(key, msg))
    elif mode == "D":
        result_var.set(decode(key, msg))
    else:
        messagebox.showerror("Error", "Invalid mode! Use 'E' for encryption or 'D' for decryption.")


# Buttons
btn_frame = Frame(root, bg="lightblue")
btn_frame.pack(pady=10)

encrypt_btn = Button(btn_frame, text="Process", font=("Arial", 12, "bold"), bg="green", fg="white",
                     command=process_message)
encrypt_btn.grid(row=0, column=0, padx=10)

reset_btn = Button(btn_frame, text="Reset", font=("Arial", 12, "bold"), bg="orange", fg="white",
                   command=lambda: [msg_entry.delete(0, END), key_entry.delete(0, END), mode_entry.delete(0, END),
                                    result_var.set("")])
reset_btn.grid(row=0, column=1, padx=10)

exit_btn = Button(btn_frame, text="Exit", font=("Arial", 12, "bold"), bg="red", fg="white", command=root.quit)
exit_btn.grid(row=0, column=2, padx=10)

root.mainloop()
