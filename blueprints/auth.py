import os
from flask import Blueprint, request, session, redirect, url_for, render_template
from werkzeug.security import check_password_hash, generate_password_hash
from database import get_db_connection

auth_bp = Blueprint('auth', __name__)

ADMIN_USUARIO = os.environ.get('ADMIN_USUARIO', 'admn')
ADMIN_SENHA = os.environ.get('ADMIN_SENHA', '992136520Fe.')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
  if request.method == 'POST':
    usuario_digitado = request.form.get('usuario', '').strip()
    senha_digitada = request.form.get('senha', '').strip()

    if usuario_digitado == ADMIN_USUARIO and senha_digitada == ADMIN_SENHA:
      session.permanent = True
      session['logado'] = True
      session['cargo'] = 'admn'
      return redirect(url_for('index'))

    conn = get_db_connection()
    try:
      membro = conn.execute(
          "SELECT * FROM equipe WHERE usuario = ? AND status_acesso = 'Ativo'",
          (usuario_digitado,),
      ).fetchone()
    finally:
      conn.close()

    if membro and check_password_hash(membro['senha'], senha_digitada):
      session.permanent = True
      session['logado'] = True
      session['cargo'] = 'secretario'
      return redirect(url_for('index'))

    return render_template('login.html', erro='Credenciais inválidas ou acesso pendente.')
  return render_template('login.html')

@auth_bp.route('/logout')
def logout():
  session.clear()
  return redirect(url_for('auth.login'))

@auth_bp.route('/solicitar_acesso', methods=['GET', 'POST'])
def solicitar_acesso():
  sucesso = None
  erro = None
  if request.method == 'POST':
    nome = request.form.get('nome')
    cargo = request.form.get('cargo')
    usuario = request.form.get('usuario', '').strip()
    senha = request.form.get('senha')
    
    conn = get_db_connection()
    try:
      existente = conn.execute('SELECT * FROM equipe WHERE usuario = ?', (usuario,)).fetchone()
      if existente:
        erro = 'Este usuário já está sendo utilizado. Escolha outro.'
      else:
        hash_senha = generate_password_hash(senha, method='pbkdf2:sha256')
        conn.execute(
            'INSERT INTO equipe (nome, cargo, usuario, senha, status_acesso) VALUES (?, ?, ?, ?, ?)',
            (nome, cargo, usuario, hash_senha, 'Pendente'),
        )
        conn.commit()
        sucesso = 'Solicitação enviada! Aguarde a liberação do administrador.'
    finally:
      conn.close()
  return render_template('solicitar_acesso.html', sucesso=sucesso, erro=erro)