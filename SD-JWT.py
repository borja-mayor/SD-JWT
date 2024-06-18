import jwt
import time
import base64
import random
import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

import xlsxwriter

def generate_keys():
    # Generar un par de claves RSA
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    private_key = key
    public_key = key.public_key()

    # Serializar las claves a formato PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Convertir las claves a cadenas de texto
    private_key_str = private_pem.decode('utf-8')
    public_key_str = public_pem.decode('utf-8')

    return private_key_str, public_key_str

def SDJWT():

    SECRET_KEY = 'secret'
    name = 'Borja'
    age = random.randint(1, 30)

    wallet_private_key_str, wallet_public_key_str = generate_keys()
    wallet_private_key = serialization.load_pem_private_key(
        wallet_private_key_str.encode('utf-8'),
        password=None,
    )

    ########################################################################
    ## EMISION #################
    ########################################################################
    start_time = time.time()



    random_number = random.randint(0, 1000000)
    ValorName = f"{random_number},name,{name}"
    DisclosureName = base64.urlsafe_b64encode(ValorName.encode()).decode()
    DigestName = hashlib.sha256(DisclosureName.encode()).hexdigest()

    random_number = random.randint(0, 1000000)
    ValorAge = f"{random_number},age,{age}"
    DisclosureAge = base64.urlsafe_b64encode(ValorAge.encode()).decode()
    DigestAge = hashlib.sha256(DisclosureAge.encode()).hexdigest()

    digests = [DigestName, DigestAge]

    # Datos de la credencial
    payload = {
        "_sd": digests,
        "public_key": wallet_public_key_str
    }

    # Emisión de SD-JWT
    encoded_jwt = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    SDJWTemi = encoded_jwt + '~' + DisclosureName + '~' + DisclosureAge + '~'

    end_time = time.time()

    timeEmision = end_time - start_time

    print(f'Tiempo de emisión SD-JWT: {timeEmision} segundos')

    ########################################################################
    ## PROCESAMIENTO#################
    ########################################################################
    # Partes del token
    start_time = time.time()
    parts = SDJWTemi.split('~')
    issuer_signed_jwt = parts[0]
    disclosures = parts[1:]

    # Firmar el JWT con la clave privada
    signature = wallet_private_key.sign(
        encoded_jwt.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Codificar la firma en base64 para incluirla en el token
    signature_b64 = base64.urlsafe_b64encode(signature).decode()

    SDJWTveri = issuer_signed_jwt + '~' + disclosures[1] + '~' + signature_b64 + '~'
    end_time = time.time()

    timeProcesamiento = end_time - start_time

    print(f'Tiempo de procesamiento SD-JWT: {timeProcesamiento} segundos')

    ########################################################################
    ## VERIFICACION #################
    ########################################################################

    start_time = time.time()

    parts = SDJWTveri.split('~')
    issuer_signed_jwt = parts[0]
    disclosure = parts[1]
    signature_b64 = parts[2]
    signature = base64.urlsafe_b64decode(signature_b64)

    # Verificar la firma con la clave pública
    decoded_jwt = jwt.decode(issuer_signed_jwt, SECRET_KEY, algorithms=['HS256'])
    try:
        public_key = serialization.load_pem_public_key(
            decoded_jwt['public_key'].encode()
        )
        public_key.verify(
            signature,
            issuer_signed_jwt.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        if hashlib.sha256(disclosure.encode()).hexdigest() in decoded_jwt['_sd']:
            valor = base64.urlsafe_b64decode(disclosure).decode()
            parts = valor.split(',')
            age = int(parts[2])

            # Comprobación de edad
            if age >= 18:
                print("Verificación de edad exitosa con SD-JWT")
            else:
                print("Verificación de edad fallida con SD-JWT")

    except Exception as e:
        print(f"Error en la verificación de la firma: {e}")

    end_time = time.time()

    timeVerificacion = end_time - start_time

    print(f'Tiempo de verificación SD-JWT: {timeVerificacion} segundos')

    tiempos = [timeEmision, timeProcesamiento, timeVerificacion]

    return tiempos

if __name__ == '__main__':
    tiempos_totales = []
    for i in range(100):
        tiempos = SDJWT()
        tiempos_totales.append(tiempos)

    # Crear un nuevo archivo Excel
    workbook = xlsxwriter.Workbook('tiempos_sd-jwt.xlsx')
    worksheet = workbook.add_worksheet()

    # Escribir los encabezados
    worksheet.write(0, 0, 'Emisión SD-JWT')
    worksheet.write(0, 1, 'Procesamiento SD-JWT')
    worksheet.write(0, 2, 'Verificación SD-JWT')

    # Escribir los tiempos en el archivo Excel
    for i, tiempos in enumerate(tiempos_totales):
        for j, tiempo in enumerate(tiempos):
            worksheet.write(i + 1, j, tiempo)

    # Cerrar el archivo Excel
    workbook.close()

    print("Los tiempos han sido exportados a 'tiempos_sd-jwt.xlsx'.")