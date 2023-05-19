import tkinter
from PIL import ImageTk, Image
import base64
from tkinter import messagebox

def Encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def Decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


window = tkinter.Tk()
window.title("SecretNotes")
window.config(padx=30, pady=30)
window.minsize(200, 700)

image = Image.open("secrett.jpg")
img = image.resize((150, 100))

my_img = ImageTk.PhotoImage(img)

image_label = tkinter.Label(image=my_img)
image_label.pack()

title_label = tkinter.Label(text="Enter your title", font=("Arial", 10, "normal"))
title_label.pack()

title_entry = tkinter.Entry(width=30)
title_entry.focus()
title_entry.pack()

text_label = tkinter.Label(text="Enter your secret", font=("Arial", 10, "normal"))
text_label.pack()

text_text = tkinter.Text(width=30, height=14)
text_text.pack()

master_key = tkinter.Label(text="Enter master key", font=("Arial", 10, "normal"))
master_key.pack()

master_key_entry = tkinter.Entry(width=30, show="*")
master_key_entry.pack()

key = tkinter.StringVar()

def save_text_and_encrypt():
    title = title_entry.get()
    text = text_text.get("1.0", tkinter.END)
    master = master_key_entry.get()

    if len(title) == 0 or len(text) == 0 or len(master) == 0:
        messagebox.showerror(title="Error!", message="Please enter all informations")

    else:
        #encryption
        message_encrypt = Encode(master, text)
        try:
            with open("test.txt", "a") as datafiles:
                datafiles.write(f"\n{title}\n{message_encrypt}")
        except:
            with open("test.txt", "w") as datafiles:
                datafiles.write(f"\n{title}\n{message_encrypt}")

        finally:
            title_entry.delete(0, tkinter.END)
            text_text.delete("1.0", tkinter.END)
            master_key_entry.delete(0, tkinter.END)


def decrypted():
    message_encrypt = text_text.get("1.0", tkinter.END)

    master = master_key_entry.get()

    if len(message_encrypt) == 0 or len(master) == 0:
        messagebox.showerror(title="Error!", message="Please enter your all informations")

    else:
        try:
            decrypted_message = Decode(master, message_encrypt)
            text_text.delete("1.0", tkinter.END)
            text_text.insert("1.0", decrypted_message)

        except:
            messagebox.showerror(title="Error!", message="Please enter encrypted text ")



save_encrypt = tkinter.Button(text="Save & Encrypt", command=save_text_and_encrypt)
save_encrypt.pack()

decrypt = tkinter.Button(text="Decrypt", command=decrypted)
decrypt.pack()

window.mainloop()