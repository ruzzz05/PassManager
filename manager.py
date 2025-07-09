import bcrypt
import json
import os
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

DB_FILE = "passwords.json"

def save(data):
    with open(DB_FILE, "w") as f:
        json.dump(data, f)

def load_db():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r") as f:
            return json.load(f)
    return {}

def derive_key(password: bytes, salt: bytes) -> bytes:
    """Deriva una clave Fernet a partir de la contraseña maestra y salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    key = kdf.derive(password)
    return urlsafe_b64encode(key)  # Fernet requiere base64 urlsafe

def crear_Master():
    password = input("Crea una contraseña para el Gestor: ").encode()
    hashed = bcrypt.hashpw(password, bcrypt.gensalt())
    salt = os.urandom(16)  # Salt para derivar la clave Fernet
    data = {
        "master": hashed.decode(),
        "salt": urlsafe_b64encode(salt).decode(),
        "entries": {},
        "fallos": 5
    }
    save(data)
    print("Contraseña maestra creada")

def verificacion(data):
    intento = input("Introduce la Master: ").encode()
    if not bcrypt.checkpw(intento, data["master"].encode()):
        return False
    salt = urlsafe_b64decode(data["salt"].encode())
    key = derive_key(intento, salt)
    return key

def introducir(data, fernet):
    nombre = input("Introduce el Apodo para esta nueva contraseña: ")
    mail = input("Introduce el usuario/mail para el inicio: ")
    password = input("Introduce la contraseña: ")

    mail_encrypted = fernet.encrypt(mail.encode()).decode()
    password_encrypted = fernet.encrypt(password.encode()).decode()

    data["entries"][nombre] = {"usuario": mail_encrypted, "password": password_encrypted}
    save(data)
    print("Correo y contraseña añadidos y cifrados")

def listado(data, fernet):
    if not data["entries"]:
        print("No hay Contraseñas que listar")
        return
    
    for nombre, info in data["entries"].items():
        try:
            usuario_decrypted = fernet.decrypt(info["usuario"].encode()).decode()
        except Exception:
            usuario_decrypted = "<Error al descifrar usuario>"

        try:
            password_decrypted = fernet.decrypt(info["password"].encode()).decode()
        except Exception:
            password_decrypted = "<Error al descifrar contraseña>"

        print(f"{nombre} - Usuario: {usuario_decrypted} - Contraseña: {password_decrypted}")

def eliminar(data):
    opcion = input("Introduce el nombre de lo que quieres eliminar: ")

    if opcion not in data["entries"]:
        print("No Existe esa Contraseña")
        return
    
    del data["entries"][opcion]
    save(data)
    print(f"Contraseña '{opcion}' eliminada")

def countDown(data):
    if "fallos" not in data:
        data["fallos"] = 5

    if data["fallos"] > 0:
        data["fallos"] -= 1
        print(f"Intentos restantes: {data['fallos']}")
    else:
        print("Has superado el número de intentos permitidos.")

    save(data)

def resetCount(data):
    data["fallos"] = 5
    save(data)

def borrar_datos():
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)

def check(data):
    # Verificar si se superó el número de intentos
    if data.get("fallos", 5) <= 0:
        print("ACCESO BLOQUEADO: Demasiados intentos fallidos.")
        print("Eliminando datos...")
        borrar_datos()
        return
    


def main():
    data = load_db()

    if "master" not in data:
        crear_Master()
        data = load_db()

    

    key = verificacion(data)
    if not key:
        countDown(data)
        print("ERROR: Contraseña maestra incorrecta")
        check(data)
        return
    else:
        resetCount(data)

    fernet = Fernet(key)

    while True:
        print("\nMenú")
        print("1. Introducir Nueva Contraseña")
        print("2. Eliminar Una Contraseña")
        print("3. Listado")
        print("4. Salir")

        opc = input(">>>> ")

        if opc == "1":
            introducir(data, fernet)
        elif opc == "2":
            eliminar(data)
        elif opc == "3":
            listado(data, fernet)
        elif opc == "4":
            break
        else:
            print("ERROR: Opción no válida")

if __name__ == "__main__":
    main()
