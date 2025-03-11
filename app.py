from flask import Flask, render_template, request, redirect, url_for, flash, session
import mysql.connector
from config import DB_CONFIG
import logging
import hashlib
import base64
import xml.etree.ElementTree as ET
from secret_key import secret_key  # Import the secret key


# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = secret_key
def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)

# Load item index XML and create a dictionary
def load_item_index():
    tree = ET.parse('static/xml/item_index.xml')
    root = tree.getroot()
    item_dict = {}
    for item in root.findall('item'):
        item_id = int(item.get('id'))
        item_name = item.get('name')
        item_dict[item_id] = item_name
    return item_dict

item_index = load_item_index()

@app.route('/')
def hello_world():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    # Convert password to SHA1 then base64 to match PHP's encoding
    password_raw = request.form.get('password')
    password_sha1 = hashlib.sha1(password_raw.encode()).digest()  # SHA1 in binary mode
    password = base64.b64encode(password_sha1).decode()  # Convert to base64
    
    logger.debug(f"Login attempt for user: {username}")
    logger.debug(f"Encoded password: {password}")  # For debugging
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT login FROM accounts 
            WHERE login = %s AND password = %s
        """, (username, password))
        
        user = cursor.fetchone()
        
        if user:
            logger.info(f"Successful login for user: {username}")
            session['username'] = user['login']  # Store only the login
            flash('Login Correcto!', 'success')
            return redirect(url_for('dashboard'))  # Redirect to dashboard instead
        else:
            logger.warning(f"Failed login attempt for user: {username}")
            flash('Login Incorrecto!', 'error')
            
    except mysql.connector.Error as err:
        logger.error(f"Database error: {err}")
        flash(f'Database error: {err}', 'error')
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()
            
    return redirect(url_for('hello_world'))

@app.route('/register', methods=['GET', 'POST'])
def show_register():
    if request.method == 'GET':
        return render_template('register.html')
    
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    
    if password != confirm_password:
        flash('Las contraseñas no son iguales', 'error')
        return redirect(url_for('show_register'))
    
    # Convert password to SHA1 then base64 to match existing format
    password_sha1 = hashlib.sha1(password.encode()).digest()
    password = base64.b64encode(password_sha1).decode()
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Check if username already exists
        cursor.execute("SELECT login FROM accounts WHERE login = %s", (username,))
        if cursor.fetchone():
            flash('Este login ya existe!', 'error')
            return redirect(url_for('show_register'))
        
        # Insert new account
        cursor.execute("""
            INSERT INTO accounts (login, password) 
            VALUES (%s, %s)
        """, (username, password))
        
        conn.commit()
        flash('Registro exitoso, ahora puedes conectarte.', 'success')
        return redirect(url_for('hello_world'))
        
    except mysql.connector.Error as err:
        logger.error(f"Database error: {err}")
        flash(f'Registro fallido: {err}', 'error')
        return redirect(url_for('show_register'))
        
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('hello_world'))
        
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Fixed column name from char_id to charId
        cursor.execute("""
            SELECT charId, char_name, level, createDate, curHp, curMp, onlinetime
            FROM characters
            WHERE account_name = %s
        """, (session['username'],))
        
        characters = cursor.fetchall()
        logger.debug(f"Characters fetched: {characters}")  # Debug log
        
        return render_template('dashboard.html', characters=characters)
        
    except mysql.connector.Error as err:
        logger.error(f"Database error: {err}")
        flash(f'Database error: {err}', 'error')
        return redirect(url_for('hello_world'))
        
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route('/character/<int:char_id>')
def character_details(char_id):
    if 'username' not in session:
        return redirect(url_for('hello_world'))
        
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get character details
        cursor.execute("""
            SELECT *
            FROM characters
            WHERE charId = %s AND account_name = %s
        """, (char_id, session['username']))
        
        character = cursor.fetchone()
        
        if not character:
            flash('Personaje no encontrado!', 'error')
            return redirect(url_for('dashboard'))
            
        # Get character's items
        cursor.execute("""
            SELECT i.*
            FROM items i
            WHERE i.owner_id = %s
            ORDER BY i.loc, i.enchant_level DESC
        """, (char_id,))
        
        items = cursor.fetchall()
        
        # Replace item IDs with names
        for item in items:
            item['item_name'] = item_index.get(item['item_id'], 'Unknown Item')
        
        return render_template('character_details.html', 
                             character=character,
                             items=items)
        
    except mysql.connector.Error as err:
        logger.error(f"Database error: {err}")
        flash(f'Database error: {err}', 'error')
        return redirect(url_for('dashboard'))
        
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route('/logout')
def logout():
    session.clear()  # Limpia toda la sesión
    flash('Has cerrado sesión correctamente', 'info')
    return redirect(url_for('hello_world'))

@app.route('/change_password', methods=['POST'])
def change_password():
    if 'username' not in session:
        return redirect(url_for('hello_world'))
    
    old_password = request.form.get('old_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if new_password != confirm_password:
        flash('Las contraseñas nuevas no coinciden', 'error')
        return redirect(url_for('dashboard'))
    
    # Hash old password for comparison
    old_password_sha1 = hashlib.sha1(old_password.encode()).digest()
    old_password_hash = base64.b64encode(old_password_sha1).decode()
    
    # Hash new password
    new_password_sha1 = hashlib.sha1(new_password.encode()).digest()
    new_password_hash = base64.b64encode(new_password_sha1).decode()
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Verify old password
        cursor.execute("""
            SELECT login FROM accounts 
            WHERE login = %s AND password = %s
        """, (session['username'], old_password_hash))
        
        if not cursor.fetchone():
            flash('Contraseña actual incorrecta', 'error')
            return redirect(url_for('dashboard'))
        
        # Update password
        cursor.execute("""
            UPDATE accounts 
            SET password = %s 
            WHERE login = %s
        """, (new_password_hash, session['username']))
        
        conn.commit()
        flash('Contraseña actualizada correctamente. Por favor, inicia sesión nuevamente.', 'success')
        
        # Clear session and redirect to login
        session.clear()
        
    except mysql.connector.Error as err:
        logger.error(f"Database error: {err}")
        flash(f'Error al cambiar la contraseña: {err}', 'error')
        return redirect(url_for('dashboard'))
        
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()
            
    # Redirect to login page instead of dashboard
    return redirect(url_for('hello_world'))

