import os
import uuid
from datetime import datetime
from flask import Blueprint, request, session, redirect, url_for, render_template
from werkzeug.security import check_password_hash, generate_password_hash
from database import get_db_connection

auth_bp = Blueprint('auth', __name__)

ADMIN_USUARIO = os.environ.get('ADMIN_USUARIO', 'admn')
ADMIN_SENHA = os.environ.get('ADMIN_SENHA', '992136520Fe.')

def registrar_ip_login(tipo_usuario):
  """Função auxiliar sênior para capturar e gravar o IP no tracking após o login com sucesso."""
  ip_visitante = request.headers.get('CF-Connecting-IP') or request.headers.get('X-Forwarded-For') or request.remote_addr
  if ip_visitante and ',' in ip_visitante:
      ip_visitante = ip_visitante.split(',')[0].strip()
  if not ip_visitante:
      ip_visitante = "IP-Oculto"

  try:
      conn = get_db_connection()
      agora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
      
      row = conn.execute('SELECT status FROM ip_tracking WHERE ip = ?', (ip_visitante,)).fetchone()
      
      if row:
          conn.execute('UPDATE ip_tracking SET last_access = ?, endpoint = ?, usuario = ?, status = ? WHERE ip = ?', 
                      (agora, 'index', tipo_usuario, 'ativo', ip_visitante))
      else:
          conn.execute('INSERT INTO ip_tracking (ip, last_access, status, endpoint, usuario) VALUES (?, ?, ?, ?, ?)', 
                      (ip_visitante, agora, 'ativo', 'index', tipo_usuario))
      conn.commit()
      conn.close()
  except Exception as e:
      print(f"Erro ao registrar IP de login: {e}")

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
  if request.method == 'POST':
    usuario_digitado = request.form.get('usuario', '').strip()
    senha_digitada = request.form.get('senha', '').strip()

    if usuario_digitado == ADMIN_USUARIO and senha_digitada == ADMIN_SENHA:
      session.permanent = True
      session['logado'] = True
      session['cargo'] = 'admn'
      
      # GERAÇÃO DO TOKEN EXCLUSIVO PARA O MASTER NO BANCO DE DADOS
      novo_token = str(uuid.uuid4())
      session['master_token'] = novo_token
      
      try:
          conn = get_db_connection()
          try:
              conn.execute("CREATE TABLE IF NOT EXISTS master_sessao (id INTEGER PRIMARY KEY, token TEXT)")
              conn.execute("DELETE FROM master_sessao") # Mantém apenas 1 token ativo globalmente
              conn.execute("INSERT INTO master_sessao (id, token) VALUES (1, ?)", (novo_token,))
              conn.commit()
          except Exception as e:
              print(f"Aviso BD Render (Master): {e}")
          finally:
              conn.close()
      except Exception as e:
          print(f"Erro de conexão BD Render (Master): {e}")
      
      # REGISTRA O IP DO ADMIN QUE ENTROU COM SUCESSO
      registrar_ip_login('Administrador')
      
      return redirect(url_for('index'))

    membro = None
    try:
        conn = get_db_connection()
        try:
          membro = conn.execute(
              "SELECT * FROM equipe WHERE usuario = ? AND status_acesso = 'Ativo'",
              (usuario_digitado,),
          ).fetchone()
        except Exception as e:
            print(f"Aviso BD Render (Consulta Equipe): {e}")
        finally:
          conn.close()
    except Exception as e:
        print(f"Erro de conexão BD Render (Equipe): {e}")

    if membro and check_password_hash(membro['senha'], senha_digitada):
      session.permanent = True
      session['logado'] = True
      session['cargo'] = 'secretario'
      
      # REGISTRA O IP DA EQUIPE QUE ENTROU COM SUCESSO
      registrar_ip_login('Equipe (Logado)')
      
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
    
    try:
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
        except Exception as e:
            erro = 'Erro interno ao processar solicitação.'
            print(f"Aviso BD Render (Gravar Solicitação): {e}")
        finally:
          conn.close()
    except Exception as e:
        erro = 'Não foi possível conectar ao banco de dados no momento.'
        print(f"Erro de conexão BD Render (Solicitação): {e}")
        
  return render_template('solicitar_acesso.html', sucesso=sucesso, erro=erro)