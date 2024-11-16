from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import firebase_admin
from firebase_admin import credentials, firestore

# Inicializa la aplicación Flask
app = Flask(__name__)
app.secret_key = 'tu_clave_secreta'



# Leer credenciales desde variables de entorno

firebase_credentials = 'pass-62814-firebase-adminsdk-9no5b-c6ce143786.json'
cred = credentials.Certificate(firebase_credentials)
firebase_admin.initialize_app(cred)
db = firestore.client()

# Ruta principal que redirige al login
@app.route('/')
def home():
    return redirect(url_for('login'))

# Ruta para el login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Consulta a la base de datos Firebase
        usuarios_ref = db.collection('usuarios')
        query = usuarios_ref.where('username', '==', username).get()

        if query:
            user = query[0].to_dict()
            # Verifica la contraseña
            if check_password_hash(user['password'], password):
                session['user_id'] = query[0].id  # Guarda el ID del usuario en la sesión
                return redirect(url_for('panel'))
            else:
                flash('Contraseña incorrecta', 'danger')
        else:
            flash('Usuario no encontrado', 'danger')

    return render_template('login.html')

# Ruta para crear un nuevo usuario
@app.route('/crear_usuario', methods=['GET', 'POST'])
def crear_usuario():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        nombre = request.form['nombre']

        # Cifra la contraseña
        hashed_password = generate_password_hash(password)

        # Crea un nuevo usuario en Firebase
        usuario = {
            'username': username,
            'password': hashed_password,
            'nombre': nombre
        }

        db.collection('usuarios').add(usuario)
        flash('Usuario creado exitosamente', 'success')
        return redirect(url_for('login'))

    return render_template('crear_usuario.html')

# Ruta para consultar registros
@app.route('/consultar_registros')
def consultar_registros():
    if 'user_id' not in session:
        flash('Por favor, inicia sesión primero', 'warning')
        return redirect(url_for('login'))
    
    registros_ref = db.collection('registros')
    registros = [doc.to_dict() for doc in registros_ref.order_by('fecha', direction=firestore.Query.DESCENDING).stream()]
    return render_template('registros.html', registros=registros)

# Ruta para el panel de control
@app.route('/panel', methods=['GET', 'POST'])
def panel():
    if 'user_id' not in session:
        flash('Por favor, inicia sesión primero', 'warning')
        return redirect(url_for('login'))

    # Obtener el estado actual de la alarma desde Firebase
    estado_ref = db.collection('estado').document('alarma')
    estado_doc = estado_ref.get()

    if estado_doc.exists:
        estado_alarma = estado_doc.to_dict().get('estado', 'Desactivada')  # Por defecto: 'Desactivada'
    else:
        # Si no existe, inicializar en la base de datos
        estado_ref.set({'estado': 'Desactivada'})
        estado_alarma = 'Desactivada'

    if request.method == 'POST':
        # Cambiar el estado de la alarma
        nuevo_estado = 'Activada' if estado_alarma == 'Desactivada' else 'Desactivada'

        # Actualizar el estado en Firebase
        estado_ref.update({'estado': nuevo_estado})

        # Obtener el ID más alto de los registros existentes
        registros_ref = db.collection('registros')
        registros_query = registros_ref.order_by('id', direction=firestore.Query.DESCENDING).limit(1).get()

        if registros_query:
            max_id = registros_query[0].to_dict().get('id', 0)
        else:
            max_id = 0  # Si no hay registros, iniciar desde 0

        # Crear un nuevo registro con el ID incrementado
        nuevo_registro = {
            'id': max_id + 1,  # Incrementar el ID
            'fecha': datetime.now().isoformat(),
            'evento': nuevo_estado,
            'usuario_id': session['user_id']
        }

        # Guardar el nuevo registro en la colección 'registros'
        registros_ref.add(nuevo_registro)

        flash(f'Alarma {nuevo_estado.lower()} exitosamente', 'success')
        estado_alarma = nuevo_estado

    return render_template('panel.html', estado_alarma=(estado_alarma == 'Activada'))


# Ruta para cerrar sesión
@app.route('/logout')
def logout():
    # Antes de cerrar sesión, solo se muestra el mensaje de "Has cerrado sesión"
    flash('Has cerrado sesión', 'success')

    # Elimina el usuario de la sesión
    session.pop('user_id', None)

    # Redirige al login después de cerrar sesión
    return redirect(url_for('login'))


# Ejecuta la aplicación
if __name__ == '__main__':
    app.run(debug=True)
