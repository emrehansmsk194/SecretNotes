from tkinter import *
from tkinter import messagebox
import base64
def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)
password = "drogbaba12"

window = Tk()
window.title("Secret Notes")
window.minsize(width=400, height=700)
window.config(pady=50)
my_img = PhotoImage(file="topsecret.png")
bg = Label(window, image=my_img)
bg.pack()

label_title = Label(text="Enter your title", font=("Arial", 15, "normal"))
label_title.pack()

entry = Entry(width=40)
entry.focus()
entry.pack()

label_secret = Label(text="Enter your secret", font=("Arial", 15, "normal"))
label_secret.pack()

text = Text(width=35, height=18)
text.pack()

label_key = Label(text="Enter a master key", font=("Arial", 15, "normal"))
label_key.pack()

entry_key = Entry(width=40)
entry_key.pack()

string_list = []

encrypted_text_string = str()


def save_encrypt():
    global string_list, encrypted_text_string
    text_string = text.get("1.0", END)
    if entry_key.get() == password:
        if len(entry.get()) == 0 or len(text_string) == 0:
            messagebox.showwarning("Warning!","Please enter all informations")
        else:
            encrypted_text_string = encode(password,text_string)
            string_list.append(encrypted_text_string)
            with open("MySecret.txt", "a") as myFile:
                myFile.write(entry.get() + "\n")
                myFile.write(str(encrypted_text_string) + "\n")
                myFile.write("\n")
    else:
        messagebox.showerror("Password Error", "Please enter the correct password!")


button1 = Button(text="Save & Encrypt", width=20)
button1.config(command=save_encrypt)
button1.place(x=120, y=530)


# print(encrypted_text_string)
def decrypt_button():
    text_string = text.get("1.0", END)
    if entry_key.get() == password:
        try:
            decrypted_string = decode(password,text_string)
            text.delete("1.0",END)
            text.insert(INSERT,decrypted_string)
        except:
            messagebox.showerror("Decryption Error!","Your encode is wrong!")

    else:
        messagebox.showerror("Password Error!", "Please enter the correct password!")


button2 = Button(text="Decrypt", width=17)
button2.config(command=decrypt_button)
button2.place(x=128, y=560)

window.mainloop()
