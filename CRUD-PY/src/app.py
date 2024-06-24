from flask import Flask, render_template, request, redirect, url_for
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64
import mysql.connector

# Conexión a la base de datos
database = mysql.connector.connect(
    host='localhost',
    user='root',
    password='',  # Aquí deberías poner tu contraseña si tienes una configurada
    database='clinica'
)

# Clave fija para cifrado AES (32 bytes para AES-256)
encryption_key = b'13123jkhasdnkhajksdh8971juuiklos'

# Configuración de la aplicación Flask
template_dir = os.path.dirname(os.path.abspath(os.path.dirname(__file__)))
template_dir = os.path.join(template_dir, 'src','templates')

app = Flask(__name__, template_folder=template_dir)

# Función para encriptar la contraseña
def encrypt_password(password):
    password_bytes = password.encode()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(password_bytes) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

# Función para desencriptar la contraseña
def decrypt_password(encrypted_password):
    encrypted_data = base64.b64decode(encrypted_password.encode())
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data.decode()

# Ruta de inicio de sesión
@app.route('/', methods=['GET', 'POST'])
def index():
    error = None
    if request.method == 'POST':
        username = request.form['txtUsuario']
        password = request.form['txtClave']

        cursor = database.cursor(dictionary=True)
        sql = "SELECT * FROM usuarios WHERE usuario = %s"
        cursor.execute(sql, (username,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            stored_password = decrypt_password(user['clave'])
            if password == stored_password:
                if user['rol'] == 'administrador':
                    return redirect(url_for('usuarios'))
                elif user['rol'] == 'comun':
                    return redirect(url_for('menu'))
                else:
                    return "Rol desconocido"
            else:
                error = 'Credenciales incorrectas'
        else:
            error = 'Credenciales incorrectas'

    return render_template('index.html', error=error)

# Ruta para mostrar la lista de usuarios
@app.route('/usuarios')
def usuarios():
    cursor = database.cursor(dictionary=True)
    cursor.execute("SELECT * FROM usuarios")
    usuarios = cursor.fetchall()
    cursor.close()
     # Desencriptar las claves de los usuarios
    for usuario in usuarios:
        usuario['clave'] = decrypt_password(usuario['clave'])
    return render_template('usuarios.html', usuarios=usuarios)

# Ruta para agregar un nuevo usuario
@app.route('/usuarios/agregar', methods=['POST'])
def agregar_usuario():
    rol = request.form['txtRol']
    puesto = request.form['txtPuesto']
    dpi = request.form['txtDpi']
    nombres = request.form['txtNombres']
    apellidos = request.form['txtApellidos']
    telefono = request.form['txtTelefono']
    direccion = request.form['txtDireccion']
    usuario = request.form['txtUsuario']
    clave = request.form['txtClave']

    # Encriptar la clave antes de guardarla en la base de datos
    clave_encriptada = encrypt_password(clave)

    cursor = database.cursor()
    sql = "INSERT INTO usuarios (rol, puesto, dpi, nombres, apellidos, telefono, direccion, usuario, clave) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)"
    data = (rol, puesto, dpi, nombres, apellidos, telefono, direccion, usuario, clave_encriptada)
    cursor.execute(sql, data)
    database.commit()
    cursor.close()

    return redirect(url_for('usuarios'))

# Ruta para eliminar un usuario
@app.route('/usuarios/eliminar/<int:id>')
def eliminar_usuario(id):
    cursor = database.cursor()
    sql = "DELETE FROM usuarios WHERE id = %s"
    cursor.execute(sql, (id,))
    database.commit()
    cursor.close()

    return redirect(url_for('usuarios'))

# Ruta para editar un usuario (página de edición)
@app.route('/usuarios/editar/<int:id>')
def editar_usuario(id):
    cursor = database.cursor(dictionary=True)
    sql = "SELECT * FROM usuarios WHERE id = %s"
    cursor.execute(sql, (id,))
    usuario = cursor.fetchone()
    cursor.close()

    # Desencriptar la clave del usuario
    usuario['clave'] = decrypt_password(usuario['clave'])

    return render_template('editar_usuario.html', usuario=usuario)

# Ruta para procesar la edición de un usuario
@app.route('/usuarios/editar_guardar/<int:id>', methods=['POST'])
def editar_guardar_usuario(id):
    rol = request.form['txtRol']
    puesto = request.form['txtPuesto']
    dpi = request.form['txtDpi']
    nombres = request.form['txtNombres']
    apellidos = request.form['txtApellidos']
    telefono = request.form['txtTelefono']
    direccion = request.form['txtDireccion']
    usuario = request.form['txtUsuario']
    clave = request.form['txtClave']

    # Encriptar la clave antes de actualizarla en la base de datos
    clave_encriptada = encrypt_password(clave)

    cursor = database.cursor()
    sql = "UPDATE usuarios SET rol=%s, puesto=%s, dpi=%s, nombres=%s, apellidos=%s, telefono=%s, direccion=%s, usuario=%s, clave=%s WHERE id = %s"
    data = (rol, puesto, dpi, nombres, apellidos, telefono, direccion, usuario, clave_encriptada, id)
    cursor.execute(sql, data)
    database.commit()
    cursor.close()

    return redirect(url_for('usuarios'))

# Ruta para mostrar el menú
@app.route('/menu')
def menu():
    return render_template('menu.html')

# Ruta para la página Doctores
@app.route('/doctores')
def doctores():
    return render_template('doctores.html')

# Ruta para la página farmacia
@app.route('/farmacia')
def farmacia():
    return render_template('farmacia.html')


# Ruta para la página Enfermeras
@app.route('/enfermeras')
def enfermeras():
    return render_template('enfermeras.html')



# Ruta para la página Ventas
@app.route('/ventas')
def ventas():
    return render_template('ventas.html')

# Ruta para la página login
@app.route('/login')
def login():
    return render_template('login.html')

# Ruta para la página formulario
@app.route('/formulario')
def formulario():
    return render_template('formulario.html')

# Ruta para la página nosotros
@app.route('/nosotros')
def nosotros():
    return render_template('nosotros.html')

# Ruta para la página servicios
@app.route('/servicios')
def servicios():
    return render_template('servicios.html')

# Ruta para la página citas
@app.route('/citas')
def citas():
    return render_template('citas.html')

# Ruta para la página Mantenimiento
@app.route('/mantenimiento')
def mantenimiento():
    return render_template('mantenimiento.html')

# Ruta para la página Reportes
@app.route('/reportes')
def reportes():
    return render_template('reportes.html')



if __name__ == '__main__':
    app.run(debug=True)
