from PIL import Image, ImageTk
import os
import tkinter as tk
from tkinter import filedialog
from cryptography.fernet import Fernet
import base64
import hashlib


# Function to switch frames and update the sidebar
def show_frame(frame):
    frame.tkraise()
    update_sidebar(frame_summaries.get(frame, ""))

# Function to generate a key from the password
def generate_key_from_password(password):
    password = password.encode()  # Encode password to bytes
    key = hashlib.sha256(password).digest()  # Hash the password and use the digest as key
    return base64.urlsafe_b64encode(key)  # Encode the key to be compatible with Fernet

# Function to encrypt an image
def encrypt_image(image_path, text_to_hide, password):
    img = Image.open(image_path).convert("RGB")
    width, height = img.size
    encoded = img.copy()

    # Generate the key from the password
    key = generate_key_from_password(password)

    # Encrypt the text to hide
    text_to_hide = text_to_hide.encode()  # Convert text to bytes
    fernet = Fernet(key)
    encrypted_text = fernet.encrypt(text_to_hide)

    # Convert the encrypted text to binary
    binary_encrypted_text = ''.join(format(byte, '08b') for byte in encrypted_text)

    # Embed the binary encrypted text into the least significant bits of the image
    index = 0
    for row in range(height):
        for col in range(width):
            if index < len(binary_encrypted_text):
                r, g, b = encoded.getpixel((col, row))
                # Modify the LSB of the red channel
                r = (r & 0xFE) | int(binary_encrypted_text[index])
                encoded.putpixel((col, row), (r, g, b))
                index += 1
            else:
                break

    # Save the encoded image
    encoded_image_path = os.path.splitext(image_path)[0] + "_encrypted.png"
    encoded.save(encoded_image_path)
    tk.messagebox.showinfo("Success", "Image successfully encrypted and saved as " + encoded_image_path)

# Function to decrypt an image
def decrypt_image(image_path, password):
    img = Image.open(image_path)
    width, height = img.size

    # Generate the key from the password
    key = generate_key_from_password(password)

    # Extract the binary data from the least significant bits of the image
    binary_data = ''
    for row in range(height):
        for col in range(width):
            r, g, b = img.getpixel((col, row))
            binary_data += str(r & 0x1)

            # Check if we have enough data to decrypt
            if len(binary_data) % 8 == 0 and len(binary_data) // 8 >= 256:  # Limit to 256 bytes or adjust as needed
                break

    # Convert the binary data back to bytes
    encrypted_bytes = int(binary_data[:2048], 2).to_bytes(len(binary_data[:2048]) // 8, byteorder='big')

    # Decrypt the text using the key
    fernet = Fernet(key)
    try:
        decrypted_message = fernet.decrypt(encrypted_bytes)
        tk.messagebox.showinfo("Decrypted Message", "The hidden message is: " + decrypted_message.decode())
    except Exception as e:
        tk.messagebox.showerror("Error", "Failed to decrypt the image. Incorrect password or corrupted image. Error: " + str(e))


# File Encrypting function
def encrypt_file(password, file_path):
    key = generate_key_from_password(password)
    fernet = Fernet(key)

    with open(file_path, 'rb') as file:
        original = file.read()
    encrypted = fernet.encrypt(original)

    with open(file_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)

    tk.messagebox.showinfo("Success", "File Successfully Encrypted!")

# File Decrypting function
def decrypt_file(password, file_path):
    key = generate_key_from_password(password)
    fernet = Fernet(key)

    with open(file_path, 'rb') as enc_file:
        encrypted = enc_file.read()
    decrypted = fernet.decrypt(encrypted)

    with open(file_path, 'wb') as dec_file:
        dec_file.write(decrypted)

    tk.messagebox.showinfo("Success", "File Successfully Decrypted!")

# Function definitions for each button
def encrypt_img():
    show_frame(encrypt_img_frame)

def decrypt_img():
    show_frame(decrypt_img_frame)

def encrypt_file_ui():
    show_frame(encrypt_file_frame)

def decrypt_file_ui():
    show_frame(decrypt_file_frame)

def show_info():
    show_frame(info_frame)

def exit_program():
    root.quit()

# Function to browse files
def browse_file():
    file_path = filedialog.askopenfilename(initialdir="/", title="Select a File")
    file_label.config(text="Selected File: " + file_path)
    return file_path

# Create the main window
root = tk.Tk()
root.title("Jcrypt Encryption & Decryption Tool")
root.geometry("1080x550")  # Set window size
root.minsize(width=1080, height=550)
root.maxsize(width=1080, height=550)
root.configure(bg='white')

#---------------top frame------------------------------------------------------------------------------------------------------------------

top_frame = tk.Frame(root, height=70, width=1080, bg='orange')
path = "images/bg.jpg"
img = ImageTk.PhotoImage(Image.open(path).resize((1080, 70), Image.Resampling.LANCZOS))
label = tk.Label(top_frame, image=img, height=70, width=1080)
label.image = img
label.place(x=0, y=0)
top_frame.place(x=0, y=0)
tf_label = tk.Label(top_frame, text='Jcrypt Tool', font='msserif 33', fg='black', bg='gray89', height=70)
tf_label.pack(anchor='center')
top_frame.pack_propagate(False)

# Load background images
head_bg_image = ImageTk.PhotoImage(Image.open("images/Head_bg.jpg").resize((1080, 480), Image.Resampling.LANCZOS))

# Create a container frame to stack all frames
container = tk.Frame(root)
container.pack(fill="both", expand=True)
container.place(x=0, y=70)  # Adjusting the container placement to account for the top frame height

# Define multiple frames
main_menu_frame = tk.Frame(container, width=1080, height=480)
encrypt_img_frame = tk.Frame(container, width=1080, height=480)
decrypt_img_frame = tk.Frame(container, width=1080, height=480)
encrypt_file_frame = tk.Frame(container, width=1080, height=480)
decrypt_file_frame = tk.Frame(container, width=1080, height=480)
info_frame = tk.Frame(container, width=1080, height=480)

for frame in (main_menu_frame, encrypt_img_frame, decrypt_img_frame, encrypt_file_frame, decrypt_file_frame, info_frame):
    frame.grid(row=0, column=0, sticky="nsew")

# Function to set the background
def set_background(frame, bg_img):
    bg_label = tk.Label(frame, image=bg_img)
    bg_label.place(x=0, y=0, relwidth=1, relheight=1)

# Set background for each frame
set_background(main_menu_frame, head_bg_image)
set_background(encrypt_img_frame, head_bg_image)
set_background(decrypt_img_frame, head_bg_image)
set_background(encrypt_file_frame, head_bg_image)
set_background(decrypt_file_frame, head_bg_image)
set_background(info_frame, head_bg_image)

# Resize images for buttons
def load_and_resize_image(path, size):
    image = Image.open(path)
    image = image.resize(size, Image.Resampling.LANCZOS)
    return ImageTk.PhotoImage(image)

# Load and resize button images
button_size = (120, 120)  # Adjusted button size for better fit
encrypt_img_image = load_and_resize_image("images/img_en.png", button_size)
decrypt_img_image = load_and_resize_image("images/img_dec.png", button_size)
encrypt_file_image = load_and_resize_image("images/Encryption_file.png", button_size)
decrypt_file_image = load_and_resize_image("images/Decryption_file.png", button_size)
info_image = load_and_resize_image("images/Info.png", button_size)
exit_image = load_and_resize_image("images/logout.png", button_size)

# Sidebar
sidebar_frame = tk.Frame(root, width=280, bg='lightgrey')
sidebar_frame.place(x=620, y=70, height=480, relwidth=0.426)

# Add the vertical green line to the left of the sidebar_frame
line_color = "green"
line_thickness = 15
separator_line = tk.Frame(root, width=line_thickness, height=480, bg=line_color)
separator_line.place(x=610, y=70)

line_color = "black"
line_thickness = 625
separator_line = tk.Frame(root, width=line_thickness, height=20, bg=line_color)
separator_line.place(x=0, y=530)

line_color = "black"
line_thickness = 455
separator_line = tk.Frame(root, width=line_thickness, height=5, bg=line_color)
separator_line.place(x=625, y=115)

sidebar_heading = tk.Label(sidebar_frame, text="Page Information", font=("Arial", 18, "bold"), bg='lightgrey')
sidebar_heading.pack(pady=10)

sidebar_body = tk.Label(sidebar_frame, text="", font=("Arial", 12), bg='lightgrey', justify="left")
sidebar_body.pack(pady=10, padx=10)

def update_sidebar(text):
    sidebar_body.config(text=text)

# Define summaries for each page
frame_summaries = {
    main_menu_frame: "**Main Menu**\n\nThis is the starting point of the Jcrypt Tool, where you\ncan navigate to different sections:\n\nEncrypt Text : Secure your text data with a\nrange of encryption algorithms.\n\nDecrypt Text : Access previously encrypted text\nusing the right decryption keys.\n\nEncrypt File : Encrypt entire files to safeguard\ntheir content from unauthorized access.\n\nDecrypt File: Recover and decrypt files\nthat were previously secured.\n\nInfo : Learn more about the Jcrypt\nTool's purpose, features, and the developer.\n\nChoose any section to get started!",
    encrypt_img_frame: "  **Image Encryption Or Stenography**\n\n  On this page, you can hide secret messages within an\n  image using steganography.\n\n  Features include:\n\n  Select Image : Browse and choose an image from your\n  system.\n\n  Text Input : Type message you want to hide in the image.\n\n  Password Protection : Add an extra layer of security by\n  setting a password.\n\n  Save Encrypted Image : Save the newly encrypted imagen\n  to a desired location.\n\n  Confirmation : Get a pop-up notification confirming that the\n  image encryption was successful.\n\n  Protect your visual data today!",
    decrypt_img_frame: "  **Image Decryption**\n\n  This page lets you extract hidden messages\n  from encrypted images using a password.\n\n  Select Encrypted Image : Choose the image that\n  contains hidden information.\n\n  Password Entry : Enter the password used during\n  encryption to unlock the content.\n\n  Decode Message : Click the button to reveal the\n  hidden text within the image.\n\n  View Message : The decoded message will be displayed\n  in a text box for easy viewing.\n\n  Effortlessly decode hidden information.",
    encrypt_file_frame: "**File Encryption**\n\n Encrypt your files quickly and securely.\n Select File: Choose the file from your system that\n you want to encrypt.\n\n Encryption Algorithms: Select the encryption technique\n that best fits your security needs.\n\n Password: Add a password to ensure only authorized\n users can decrypt the file.\n\n Save Encrypted File: Save the encrypted file\n to a location of your choice.\n\n File Encryption Completed: Get a notification when the\n encryption is complete.\n Keep your files safe from unauthorized access.",
    decrypt_file_frame: "This page is for decrypting files that have been encrypted. Choose the encrypted file and use the tools to decrypt it.",
    info_frame: "The information page provides details about the Jcrypt Tool, including its purpose and developer information."
}

# Create buttons with labels and lines
button_images = [encrypt_img_image, decrypt_img_image, encrypt_file_image, decrypt_file_image, info_image, exit_image]
button_texts = ["Encrypt Image", "Decrypt Image", "Encrypt File", "Decrypt File", "Info", "Exit"]
button_commands = [encrypt_img, decrypt_img, encrypt_file_ui, decrypt_file_ui, show_info, exit_program]

for i, (img, text, cmd) in enumerate(zip(button_images, button_texts, button_commands)):
    col = i % 3
    row = i // 3 + 1

    button_frame = tk.Frame(main_menu_frame, bd=2, relief="solid", bg="lightblue")
    button_frame.grid(row=row, column=col, padx=30, pady=20, sticky="n")

    tk.Button(button_frame, image=img, command=cmd, height=120, width=120).pack(pady=5)
    label = tk.Label(button_frame, text=text, font=("Arial", 14, "bold"), bg="lightblue")
    label.pack(pady=5)
    tk.Frame(button_frame, height=3, width=140, bg="blue").pack(pady=5)

# Encrypt Image Frame
tk.Label(encrypt_img_frame, text="Encrypt Image", font=("Arial", 28), bg="lightblue").pack(pady=10)
image_label_encrypt = tk.Label(encrypt_img_frame, text="No image selected", font=("Arial", 12), bg="lightblue")
image_label_encrypt.pack(pady=10)
tk.Button(encrypt_img_frame, text="Browse Image", command=lambda: image_label_encrypt.config(text="Selected Image: " + browse_file())).pack(pady=5)
tk.Label(encrypt_img_frame, text="Enter Text to Hide:", font=("Arial", 14), bg="lightblue").pack(pady=10)
text_entry_encrypt = tk.Entry(encrypt_img_frame, font=("Arial", 14), width=40)
text_entry_encrypt.pack(pady=5)
tk.Label(encrypt_img_frame, text="Enter Password:", font=("Arial", 14), bg="lightblue").pack(pady=10)
password_entry_img_encrypt = tk.Entry(encrypt_img_frame, show='*', font=("Arial", 14), width=20)
password_entry_img_encrypt.pack(pady=5)
tk.Button(encrypt_img_frame, text="Encrypt Image", font=("Arial", 14), command=lambda: encrypt_image(image_label_encrypt.cget("text").replace("Selected Image: ", ""), text_entry_encrypt.get(), password_entry_img_encrypt.get())).pack(pady=20)
tk.Button(encrypt_img_frame, text="Back to Main Menu", command=lambda: show_frame(main_menu_frame)).pack(pady=20)

# Decrypt Image Frame
tk.Label(decrypt_img_frame, text="Decrypt Image", font=("Arial", 28), bg="lightblue").pack(pady=10)
image_label_decrypt = tk.Label(decrypt_img_frame, text="No image selected", font=("Arial", 12), bg="lightblue")
image_label_decrypt.pack(pady=10)
tk.Button(decrypt_img_frame, text="Browse Image", command=lambda: image_label_decrypt.config(text="Selected Image: " + browse_file())).pack(pady=5)
tk.Label(decrypt_img_frame, text="Enter Password:", font=("Arial", 14), bg="lightblue").pack(pady=10)
password_entry_img_decrypt = tk.Entry(decrypt_img_frame, show='*', font=("Arial", 14), width=20)
password_entry_img_decrypt.pack(pady=5)
tk.Button(decrypt_img_frame, text="Decrypt Image", font=("Arial", 14), command=lambda: decrypt_image(image_label_decrypt.cget("text").replace("Selected Image: ", ""), password_entry_img_decrypt.get())).pack(pady=20)
tk.Button(decrypt_img_frame, text="Back to Main Menu", command=lambda: show_frame(main_menu_frame)).pack(pady=20)

# Encrypt File Frame
tk.Label(encrypt_file_frame, text="Encrypt File Page", font=("Arial", 28), bg="lightblue").pack(pady=20)
file_label = tk.Label(encrypt_file_frame, text="No file selected", font=("Arial", 12), bg="lightblue")
file_label.pack(pady=10)
tk.Button(encrypt_file_frame, text="Browse File", command=browse_file).pack(pady=5)
tk.Label(encrypt_file_frame, text="Enter Password:", font=("Arial", 14), bg="lightblue").pack(pady=10)
password_entry_encrypt = tk.Entry(encrypt_file_frame, show='*', font=("Arial", 14), width=20)
password_entry_encrypt.pack(pady=5)
tk.Button(encrypt_file_frame, text="Encrypt File", font=("Arial", 14), command=lambda: encrypt_file(password_entry_encrypt.get(), file_label.cget("text").replace("Selected File: ", ""))).pack(pady=20)
tk.Button(encrypt_file_frame, text="Back to Main Menu", command=lambda: show_frame(main_menu_frame)).pack(pady=20)

# Decrypt File Frame
tk.Label(decrypt_file_frame, text="Decrypt File Page", font=("Arial", 28), bg="lightblue").pack(pady=20)
file_label_decrypt = tk.Label(decrypt_file_frame, text="No file selected", font=("Arial", 12), bg="lightblue")
file_label_decrypt.pack(pady=10)
tk.Button(decrypt_file_frame, text="Browse File", command=lambda: file_label_decrypt.config(text="Selected File: " + browse_file())).pack(pady=5)
tk.Label(decrypt_file_frame, text="Enter Password:", font=("Arial", 14), bg="lightblue").pack(pady=10)
password_entry_decrypt = tk.Entry(decrypt_file_frame, show='*', font=("Arial", 14), width=20)
password_entry_decrypt.pack(pady=5)
tk.Button(decrypt_file_frame, text="Decrypt File", font=("Arial", 14), command=lambda: decrypt_file(password_entry_decrypt.get(), file_label_decrypt.cget("text").replace("Selected File: ", ""))).pack(pady=20)
tk.Button(decrypt_file_frame, text="Back to Main Menu", command=lambda: show_frame(main_menu_frame)).pack(pady=20)

# Info Frame
tk.Label(info_frame, text="Information Page", font=("Arial", 28), bg="lightblue").pack(pady=30)
tk.Label(info_frame, text="This software was developed by Himanshu Kumar.", font=("Arial", 18), bg="lightblue").pack(pady=20)
tk.Button(info_frame, text="Back to Main Menu", command=lambda: show_frame(main_menu_frame)).pack()

# Show the main menu first
show_frame(main_menu_frame)

# Run the application
root.mainloop()
