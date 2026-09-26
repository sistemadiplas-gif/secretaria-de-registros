import os
import random
from datetime import timedelta, datetime
from functools import wraps
from flask import (
    Flask,
    abort,
    redirect,
    render_template,
    render_template_string,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask_wtf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# --- NOSSOS NOVOS MÓDULOS (BLUEPRINTS E BANCO) ---
from database import get_db_connection, init_db
from blueprints.auth import auth_bp

app = Flask(__name__)

# REGISTRANDO O BLUEPRINT DE AUTENTICAÇÃO
app.register_blueprint(auth_bp)

# ==========================================
# CONFIGURAÇÕES DE SEGURANÇA SÊNIOR
# ==========================================
app.secret_key = os.environ.get('SECRET_KEY', 'kR9#m2Pq!v8Z$xL5@nW3*yT7^c4F1bN0')

csrf = CSRFProtect(app)

EM_PRODUCAO = 'RENDER' in os.environ

app.config['SESSION_COOKIE_SECURE'] = EM_PRODUCAO
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=50)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

app.wsgi_app = ProxyFix(
    app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
)

UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
  os.makedirs(UPLOAD_FOLDER)

ADMIN_USUARIO = os.environ.get('ADMIN_USUARIO', 'admn')
ADMIN_SENHA = os.environ.get('ADMIN_SENHA', '992136520Fe.')

# ==========================================
# TRATAMENTO DE ERROS PERSONALIZADOS
# ==========================================
@app.errorhandler(404)
def pagina_nao_encontrada(e):
    return render_template_string('''
        <div style="font-family: Arial; text-align: center; padding-top: 100px;">
            <h1 style="color: #8a1c22; font-size: 50px;">404</h1>
            <h2>Página não encontrada</h2>
            <p style="color: #666;">O documento ou portal que está a tentar aceder não existe ou foi movido.</p>
            <a href="/" style="text-decoration: none; color: white; background: #8a1c22; padding: 10px 20px; border-radius: 5px; display: inline-block; margin-top: 20px;">Voltar ao Início</a>
        </div>
    '''), 404

@app.errorhandler(500)
def erro_interno_servidor(e):
    return render_template_string('''
        <div style="font-family: Arial; text-align: center; padding-top: 100px;">
            <h1 style="color: #333; font-size: 50px;">500</h1>
            <h2>Erro Interno do Servidor</h2>
            <p style="color: #666;">Ocorreu um erro temporário no servidor de base de dados. Por favor, volte ao ecrã inicial e tente novamente.</p>
            <a href="/" style="text-decoration: none; color: white; background: #333; padding: 10px 20px; border-radius: 5px; display: inline-block; margin-top: 20px;">Voltar ao Início</a>
        </div>
    '''), 500

# ==========================================
# MAPEAMENTO DE DOMÍNIOS
# ==========================================
DOMINIOS_MAPA = {
    'painel': 'https://secretariaregistrosgovbr.com',
    'consulta_xml': 'https://http-verficadordiplomadigitalmecgovbr.com',
    'dou': 'https://http-govbr.com',
    'cna': 'https://https-cna-oab-org-br.com',
    'confea': 'https://https-consultaprofissional-confea-org-br.com',
    'estacio': 'https://http-sia-estaciobr.com', 
    'puc_sp': 'https://portal-fundasp-org-br.com',
    'puc_mg': 'https://web-sistemas-pucminas-br.com',
    'unip': 'https://http-unipbr.com',
    'anhanguera': 'https://https-login-anhanguera.com',
}

def obter_url_base_faculdade(slug):
  if slug == 'unip':
    return DOMINIOS_MAPA['unip']
  elif slug == 'sia_estacio_br':
    return DOMINIOS_MAPA['estacio']
  elif slug == 'puc_sp':
    return DOMINIOS_MAPA['puc_sp']
  elif slug == 'puc_mg':
    return DOMINIOS_MAPA['puc_mg']
  elif slug == 'anhanguera':
    return DOMINIOS_MAPA['anhanguera']
  else:
    return DOMINIOS_MAPA['unip']

def normalizar_cpf(cpf):
  return ''.join(filter(str.isdigit, str(cpf or '')))

@app.after_request
def aplicar_headers_seguranca(response):
  response.headers['X-Content-Type-Options'] = 'nosniff'
  response.headers['X-Frame-Options'] = 'SAMEORIGIN'
  response.headers['X-XSS-Protection'] = '1; mode=block'
  response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
  response.headers['Pragma'] = 'no-cache'
  response.headers['Expires'] = '0'
  if EM_PRODUCAO:
    response.headers['Strict-Transport-Security'] = (
        'max-age=31536000; includeSubDomains'
    )
  return response

init_db()

# ==========================================
# GESTÃO INTELIGENTE DA TABELA DE FIREWALL
# ==========================================
def criar_tabela_firewall_se_nao_existir():
    conn = get_db_connection()
    try:
        conn.execute("DROP TABLE IF EXISTS ip_tracking")
        conn.execute('''
            CREATE TABLE ip_tracking (
                ip TEXT PRIMARY KEY,
                last_access TIMESTAMP,
                status TEXT,
                endpoint TEXT,
                usuario TEXT
            )
        ''')
        conn.commit()
    except Exception as e:
        print(f"Erro ao forçar tabela firewall: {e}")
    finally:
        conn.close()

criar_tabela_firewall_se_nao_existir()

# ==========================================
# FUNÇÕES DE UPLOAD E VALIDAÇÃO DE EXTENSÃO
# ==========================================
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def salvar_arquivo(file_storage):
  if file_storage and file_storage.filename != '':
    if allowed_file(file_storage.filename):
        filename = secure_filename(file_storage.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file_storage.save(filepath)
        return filename
  return ''

def salvar_multiplos_arquivos(file_storage_list, antigos=''):
  nomes_salvos = [f for f in antigos.split('|') if f.strip()] if antigos else []
  for f in file_storage_list:
    if f and f.filename != '':
      if allowed_file(f.filename):
          filename = secure_filename(f.filename)
          filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
          f.save(filepath)
          if filename not in nomes_salvos:
            nomes_salvos.append(filename)
  return '|'.join(nomes_salvos) if nomes_salvos else ''

# ==========================================
# ROTEADOR DE DOMÍNIOS E FIREWALL CLOUDFLARE
# ==========================================
@app.before_request
def travar_dominios_e_autenticacao():
  session.modified = True

  if request.endpoint == 'static':
    return

  ip_visitante = request.headers.get('CF-Connecting-IP')
  if not ip_visitante:
      ip_visitante = request.headers.get('X-Forwarded-For')
  if not ip_visitante:
      ip_visitante = request.remote_addr
  
  if ip_visitante and ',' in ip_visitante:
      ip_visitante = ip_visitante.split(',')[0].strip()

  if not ip_visitante:
      ip_visitante = "IP-Oculto"

  usuario_atual = 'Visitante Público'
  if session.get('logado'):
      if session.get('cargo') == 'admn':
          usuario_atual = 'Administrador'
      else:
          usuario_atual = 'Equipe (Logado)'

  host = request.host.lower()
  
  # NOVA REGRA: Define se o acesso está a ser feito através do domínio principal ou de testes locais
  is_painel = 'secretariaregistrosgovbr' in host or 'localhost' in host or '127.0.0.1' in host or 'onrender' in host

  try:
      conn = get_db_connection()
      try:
          agora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
          row = conn.execute('SELECT status, usuario FROM ip_tracking WHERE ip = ?', (ip_visitante,)).fetchone()
          
          if row:
              novo_status = row['status']
              if usuario_atual == 'Administrador' or row['usuario'] == 'Administrador':
                  novo_status = 'ativo'

              # A regra de bloqueio aplica-se a todos os domínios
              if novo_status == 'bloqueado' and usuario_atual != 'Administrador':
                  return "ACESSO NEGADO. O seu endereço de IP foi bloqueado permanentemente por atividade suspeita.", 403
                  
              # O IP só é atualizado na lista visual se estiver a aceder ao painel
              if is_painel:
                  conn.execute('UPDATE ip_tracking SET last_access = ?, endpoint = ?, usuario = ?, status = ? WHERE ip = ?', 
                              (agora, request.endpoint or 'desconhecido', usuario_atual, novo_status, ip_visitante))
          else:
              # Se o IP não existe, SÓ O GRAVA se estiver a tentar aceder ao painel
              if is_painel:
                  conn.execute('INSERT INTO ip_tracking (ip, last_access, status, endpoint, usuario) VALUES (?, ?, ?, ?, ?)', 
                              (ip_visitante, agora, 'ativo', request.endpoint or 'desconhecido', usuario_atual))
          conn.commit()
      except Exception:
          pass
      finally:
          conn.close()
  except Exception:
      pass

  if 'http-verficadordiplomadigitalmecgovbr' in host:
    rotas_xml = ['consulta_xml', 'consulta_xml_direta']
    if request.endpoint not in rotas_xml:
      return redirect(url_for('consulta_xml'))

  elif 'http-govbr' in host:
    rotas_dou = ['imprensanacional_busca', 'imprensanacional_consulta']
    if request.endpoint not in rotas_dou:
      return redirect(url_for('imprensanacional_busca'))

  elif 'https-cna-oab' in host:
    if request.endpoint != 'conselho_oab':
      return "Acesso restrito. Utilize o link com o ID direto da consulta CNA.", 403

  elif 'https-consultaprofissional-confea' in host:
    if request.endpoint != 'conselho_confea':
      return "Acesso restrito. Utilize o link com o ID direto da consulta Confea.", 403

  elif 'http-sia-estaciobr' in host or 'portal-fundasp-org-br' in host or 'web-sistemas-pucminas-br' in host or 'http-unipbr' in host or 'https-login-anhanguera' in host:
    rotas_portais = [
        'portal_do_aluno_publico', 'validacao_qr_code', 
        'visualizar_qrcode', 'visualizar_documento', 'download_file'
    ]
    if request.endpoint not in rotas_portais:
      return "Acesso restrito ao portal do aluno. Utilize o link oficial do seu QR Code ou Matrícula.", 403

  else:
    rotas_livres = [
        'auth.login', 'auth.solicitar_acesso', 'portal_do_aluno_publico', 'validacao_qr_code', 
        'consulta_xml', 'consulta_xml_direta', 'imprensanacional_consulta', 'imprensanacional_busca', 
        'download_file', 'visualizar_documento', 'conselho_oab', 'conselho_confea', 'visualizar_qrcode', 'gerar_posse', 'gerar_exercicio'
    ]
    if request.endpoint not in rotas_livres and not session.get('logado'):
      return redirect(url_for('auth.login'))

def somente_admn(f):
  @wraps(f)
  def wrapper(*args, **kwargs):
    if session.get('cargo') != 'admn':
      abort(403)
    return f(*args, **kwargs)
  return wrapper

# ==========================================
# ROTAS DO FIREWALL (SÓ PARA ADMIN)
# ==========================================
@app.route('/bloquear_ip/<ip>', methods=['POST'])
@somente_admn
def bloquear_ip(ip):
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT usuario FROM ip_tracking WHERE ip = ?", (ip,)).fetchone()
        if row and row['usuario'] == 'Administrador':
            pass
        else:
            conn.execute("UPDATE ip_tracking SET status = 'bloqueado' WHERE ip = ?", (ip,))
            conn.commit()
    except Exception:
        pass
    finally:
        conn.close()
    return redirect(url_for('index'))

@app.route('/desbloquear_ip/<ip>', methods=['POST'])
@somente_admn
def desbloquear_ip(ip):
    conn = get_db_connection()
    try:
        conn.execute("UPDATE ip_tracking SET status = 'ativo' WHERE ip = ?", (ip,))
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()
    return redirect(url_for('index'))

# ==========================================
# ROTAS DO SISTEMA INTERNO
# ==========================================
@app.route('/')
def index():
  conn = get_db_connection()
  total_alunos = 0
  equipe_ativa = []
  equipe_pendente = []
  ips_monitorados = []
  
  try:
      resultado = conn.execute('SELECT COUNT(*) FROM alunos').fetchone()
      if resultado:
          total_alunos = resultado[0]
  except Exception:
      pass

  try:
      equipe_ativa = conn.execute("SELECT * FROM equipe WHERE status_acesso = 'Ativo'").fetchall()
  except Exception:
      pass

  try:
      equipe_pendente = conn.execute("SELECT * FROM equipe WHERE status_acesso = 'Pendente'").fetchall()
  except Exception:
      pass

  try:
      ips_monitorados = conn.execute("SELECT * FROM ip_tracking ORDER BY last_access DESC LIMIT 50").fetchall()
  except Exception:
      pass

  conn.close()
    
  return render_template(
      'index.html', 
      total=total_alunos, 
      ativos=equipe_ativa, 
      pendentes=equipe_pendente,
      ips_monitorados=ips_monitorados
  )

@app.route('/aprovar_equipe/<int:id>', methods=['POST'])
@somente_admn
def aprovar_equipe(id):
  conn = get_db_connection()
  try:
    conn.execute("UPDATE equipe SET status_acesso = 'Ativo' WHERE id = ?", (id,))
    conn.commit()
  except Exception:
      pass
  finally:
    conn.close()
  return redirect(url_for('index'))

@app.route('/remover_equipe/<int:id>', methods=['POST'])
@somente_admn
def remover_equipe(id):
  conn = get_db_connection()
  try:
    conn.execute('DELETE FROM equipe WHERE id = ?', (id,))
    conn.commit()
  except Exception:
      pass
  finally:
    conn.close()
  return redirect(url_for('index'))

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
  if request.method == 'POST':
    dados = request.form
    foto_file = request.files.get('foto_file')
    frente_file = request.files.get('diploma_frente_file')
    verso_file = request.files.get('diploma_verso_file')
    cert_files = request.files.getlist('certificado_file')
    hist_files = request.files.getlist('historico_file')
    outros_files = request.files.getlist('outros_file')

    foto = salvar_arquivo(foto_file) or dados.get('foto_antiga', '')
    diploma_frente = salvar_arquivo(frente_file) or dados.get('frente_antiga', '')
    diploma_verso = salvar_arquivo(verso_file) or dados.get('verso_antiga', '')
    certificado = salvar_multiplos_arquivos(cert_files, dados.get('cert_antigo', ''))
    historico = salvar_multiplos_arquivos(hist_files, dados.get('hist_antigo', ''))
    outros_docs = salvar_multiplos_arquivos(outros_files, dados.get('outros_antigo', ''))

    cpf = normalizar_cpf(dados['cpf'])

    conn = get_db_connection()
    try:
      duplicado = conn.execute('SELECT nome FROM alunos WHERE cpf = ?', (cpf,)).fetchone()
      
      if duplicado:
          return f"Erro: O CPF digitado já está cadastrado para o aluno(a) {duplicado['nome']}. Volte a página e verifique os dados.", 400

      conn.execute(
          '''
              INSERT INTO alunos (
                  nome, cpf, rg, orgao_rg, data_expedicao, data_nascimento, naturalidade, filiacao, endereco, foto, 
                  tipo_curso, curso, grau_academico, instituicao_ensino, data_inicio, data_conclusao, 
                  carga_horaria, matricula, registro_validacao, gerar_qrcode, 
                  diploma_frente, diploma_verso, certificado, historico, outros_docs,
                  edital_concurso, data_homologacao, dados_nomeacao, data_posse, data_exercicio, esfera_concurso, local_esfera,
                  orgao, numero_registro, uf_registro, faculdade_slug
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ''',
          (
              dados['nome'], cpf, dados['rg'], dados['orgao_rg'], dados['data_expedicao'],
              dados['data_nascimento'], dados['naturalidade'], dados['filiacao'], dados['endereco'], foto,
              dados['tipo_curso'], dados['curso'], dados.get('grau_academico', ''),
              dados.get('instituicao_ensino', ''), dados.get('data_inicio', ''),
              dados.get('data_conclusao', ''), dados.get('carga_horaria', ''), dados['matricula'],
              dados.get('registro_validacao', ''), dados.get('gerar_qrcode', 'Não'),
              diploma_frente, diploma_verso, certificado, historico, outros_docs,
              dados.get('edital_concurso', ''), dados.get('data_homologacao', ''),
              dados.get('dados_nomeacao', ''), dados.get('data_posse', ''), dados.get('data_exercicio', ''),
              dados.get('esfera_concurso', 'Federal'), dados.get('local_esfera', ''),
              dados.get('orgao', ''), dados.get('numero_registro', ''),
              dados.get('uf_registro', ''), dados.get('faculdade_slug', 'unip'),
          ),
      )
      conn.commit()
    except Exception as e:
        return f"Erro de banco de dados ao salvar: {e}", 500
    finally:
      conn.close()

    return redirect(url_for('cadastro'))
  return render_template('cadastro.html')

@app.route('/alterar', methods=['GET', 'POST'])
def alterar():
  conn = get_db_connection()
  alunos = []
  try:
    if request.method == 'POST':
      termo = request.form.get('termo', '').strip()
      if termo:
          alunos = conn.execute(
              'SELECT * FROM alunos WHERE nome LIKE ? OR cpf = ? ORDER BY nome ASC',
              ('%' + termo + '%', normalizar_cpf(termo)),
          ).fetchall()
      else:
          alunos = conn.execute('SELECT * FROM alunos ORDER BY nome ASC').fetchall()
    else:
      alunos = conn.execute('SELECT * FROM alunos ORDER BY nome ASC').fetchall()
  except Exception:
      pass
  finally:
    conn.close()
    
  return render_template('alterar.html', alunos=alunos)

@app.route('/editar/<int:id>', methods=['GET', 'POST'])
def editar(id):
  conn = get_db_connection()
  if request.method == 'POST':
    dados = request.form
    foto_file = request.files.get('foto_file')
    frente_file = request.files.get('diploma_frente_file')
    verso_file = request.files.get('diploma_verso_file')
    cert_files = request.files.getlist('certificado_file')
    hist_files = request.files.getlist('historico_file')
    outros_files = request.files.getlist('outros_file')

    foto = salvar_arquivo(foto_file) or dados.get('foto_antiga', '')
    diploma_frente = salvar_arquivo(frente_file) or dados.get('frente_antiga', '')
    diploma_verso = salvar_arquivo(verso_file) or dados.get('verso_antiga', '')
    certificado = salvar_multiplos_arquivos(cert_files, dados.get('cert_antigo', ''))
    historico = salvar_multiplos_arquivos(hist_files, dados.get('hist_antigo', ''))
    outros_docs = salvar_multiplos_arquivos(outros_files, dados.get('outros_antigo', ''))

    cpf = normalizar_cpf(dados['cpf'])

    try:
      duplicado = conn.execute(
          'SELECT nome FROM alunos WHERE cpf = ? AND id != ?', 
          (cpf, id)
      ).fetchone()
      
      if duplicado:
          return f"Erro: O CPF digitado já pertence ao aluno(a) {duplicado['nome']}. Volte a página e corrija os dados.", 400

      conn.execute(
          '''
              UPDATE alunos SET 
                  nome = ?, cpf = ?, rg = ?, orgao_rg = ?, data_expedicao = ?, 
                  data_nascimento = ?, naturalidade = ?, filiacao = ?, endereco = ?, foto = ?,
                  tipo_curso = ?, curso = ?, grau_academico = ?, instituicao_ensino = ?, 
                  data_inicio = ?, data_conclusao = ?, carga_horaria = ?, matricula = ?, 
                  registro_validacao = ?, gerar_qrcode = ?, 
                  diploma_frente = ?, diploma_verso = ?, certificado = ?, historico = ?, outros_docs = ?,
                  edital_concurso = ?, data_homologacao = ?, dados_nomeacao = ?, data_posse = ?, data_exercicio = ?, 
                  esfera_concurso = ?, local_esfera = ?,
                  orgao = ?, numero_registro = ?, uf_registro = ?, faculdade_slug = ?
              WHERE id = ?
          ''',
          (
              dados['nome'], cpf, dados['rg'], dados['orgao_rg'], dados['data_expedicao'],
              dados['data_nascimento'], dados['naturalidade'], dados['filiacao'], dados['endereco'], foto,
              dados['tipo_curso'], dados['curso'], dados.get('grau_academico', ''),
              dados.get('instituicao_ensino', ''), dados.get('data_inicio', ''),
              dados.get('data_conclusao', ''), dados.get('carga_horaria', ''), dados['matricula'],
              dados.get('registro_validacao', ''), dados.get('gerar_qrcode', 'Não'),
              diploma_frente, diploma_verso, certificado, historico, outros_docs,
              dados.get('edital_concurso', ''), dados.get('data_homologacao', ''),
              dados.get('dados_nomeacao', ''), dados.get('data_posse', ''), dados.get('data_exercicio', ''),
              dados.get('esfera_concurso', 'Federal'), dados.get('local_esfera', ''),
              dados.get('orgao', ''), dados.get('numero_registro', ''),
              dados.get('uf_registro', ''), dados.get('faculdade_slug', 'unip'),
              id,
          ),
      )
      conn.commit()
    except Exception as e:
        return f"Erro ao atualizar dados: {e}", 500
    finally:
      conn.close()

    return redirect(url_for('alterar'))
  
  aluno = None
  try:
    aluno = conn.execute('SELECT * FROM alunos WHERE id = ?', (id,)).fetchone()
  except Exception:
      pass
  finally:
    conn.close()
    
  return render_template('editar.html', aluno=aluno)

@app.route('/excluir', methods=['GET', 'POST'])
def excluir():
  conn = get_db_connection()
  alunos = []
  try:
    if request.method == 'POST':
      termo = request.form.get('termo', '').strip()
      if termo:
          alunos = conn.execute(
              'SELECT * FROM alunos WHERE nome LIKE ? OR cpf = ? ORDER BY nome ASC',
              ('%' + termo + '%', normalizar_cpf(termo)),
          ).fetchall()
      else:
          alunos = conn.execute('SELECT * FROM alunos ORDER BY nome ASC').fetchall()
    else:
      alunos = conn.execute('SELECT * FROM alunos ORDER BY nome ASC').fetchall()
  except Exception:
      pass
  finally:
    conn.close()
    
  return render_template('excluir.html', alunos=alunos)

@app.route('/deletar/<int:id>', methods=['POST'])
def deletar(id):
  conn = get_db_connection()
  try:
    aluno = conn.execute('SELECT * FROM alunos WHERE id = ?', (id,)).fetchone()
    if aluno:
      colunas_arquivos = ['foto', 'diploma_frente', 'diploma_verso', 'certificado', 'historico', 'outros_docs']
      for coluna in colunas_arquivos:
        if aluno[coluna]:
          arquivos = str(aluno[coluna]).split('|')
          for arq in arquivos:
            if arq.strip():
              filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(arq.strip()))
              try:
                if os.path.exists(filepath):
                  os.remove(filepath)
              except Exception:
                pass
                
    conn.execute('DELETE FROM alunos WHERE id = ?', (id,))
    conn.commit()
  except Exception:
      pass
  finally:
    conn.close()
  return redirect(url_for('excluir'))

@app.route('/deletar_todos', methods=['POST'])
@somente_admn
def deletar_todos():
  senha_confirmacao = request.form.get('senha_confirmacao', '')
  if senha_confirmacao != ADMIN_SENHA:
    abort(403)
    
  pasta_uploads = app.config['UPLOAD_FOLDER']
  if os.path.exists(pasta_uploads):
    for filename in os.listdir(pasta_uploads):
      filepath = os.path.join(pasta_uploads, filename)
      try:
        if os.path.isfile(filepath):
          os.remove(filepath)
      except Exception:
        pass
        
  conn = get_db_connection()
  try:
    conn.execute('DELETE FROM alunos')
    conn.commit()
  except Exception:
      pass
  finally:
    conn.close()
  return redirect(url_for('excluir'))

@app.route('/informacoes/<tipo>', methods=['GET', 'POST'])
def informacoes(tipo):
  titulo = 'Dossiê de Graduações e Consultas'
  conn = get_db_connection()
  alunos = []
  try:
    if request.method == 'POST':
      termo = request.form.get('termo', '').strip()
      if termo:
          alunos = conn.execute(
              'SELECT * FROM alunos WHERE nome LIKE ? OR cpf = ? ORDER BY nome ASC',
              ('%' + termo + '%', normalizar_cpf(termo)),
          ).fetchall()
      else:
          alunos = conn.execute('SELECT * FROM alunos ORDER BY nome ASC').fetchall()
    else:
      alunos = conn.execute('SELECT * FROM alunos ORDER BY nome ASC').fetchall()
  except Exception:
      pass
  finally:
    conn.close()
    
  return render_template(
      'informacoes.html', alunos=alunos, tipo=tipo, titulo=titulo
  )

@app.route('/painel_aluno/<int:id>')
def painel_aluno(id):
  conn = get_db_connection()
  aluno = None
  try:
    aluno = conn.execute('SELECT * FROM alunos WHERE id = ?', (id,)).fetchone()
  except Exception:
      pass
  finally:
    conn.close()
    
  if not aluno:
    return 'Aluno não encontrado.', 404

  slug = aluno['faculdade_slug'] if aluno['faculdade_slug'] else 'unip'
  dominio_faculdade = obter_url_base_faculdade(slug)

  url_base_custom = {
      'painel': DOMINIOS_MAPA['painel'] + '/',
      'xml': DOMINIOS_MAPA['consulta_xml'] + '/',
      'dou': DOMINIOS_MAPA['dou'] + '/',
      'cna': DOMINIOS_MAPA['cna'] + '/',
      'confea': DOMINIOS_MAPA['confea'] + '/',
      'portal': dominio_faculdade + '/',
      'validacao': f'{dominio_faculdade}/validacao/{slug}/',
  }

  return render_template('painel_aluno.html', aluno=aluno, url_base=url_base_custom)

@app.route('/portal_aluno/<cpf>', methods=['GET', 'POST'])
def portal_do_aluno_publico(cpf):
  cpf_limpo = normalizar_cpf(cpf)
  conn = get_db_connection()
  aluno = None
  try:
    aluno = conn.execute(
        'SELECT * FROM alunos WHERE cpf = ? OR matricula = ?', (cpf_limpo, cpf)
    ).fetchone()
  except Exception:
      pass
  finally:
    conn.close()
    
  if not aluno:
    return 'Cadastro não encontrado. Verifique se o link possui o CPF ou matrícula correta.', 404

  faculdade_slug = (
      aluno['faculdade_slug'] if aluno['faculdade_slug'] else 'unip'
  )

  logado_portal = False
  erro = None

  if request.method == 'POST':
    senha_digitada = ''.join(
        filter(str.isdigit, request.form.get('senha', ''))
    )
    cpf_banco = normalizar_cpf(aluno['cpf'])

    if senha_digitada and senha_digitada == cpf_banco:
      logado_portal = True
    else:
      erro = 'Senha inválida (utilize o CPF).'

  try:
    return render_template(
        f'portais/portal_{faculdade_slug}.html',
        aluno=aluno,
        url_base=request.host_url,
        logado_portal=logado_portal,
        erro=erro,
    )
  except Exception:
    try:
      return render_template(
          f'portais/{faculdade_slug}.html',
          aluno=aluno,
          url_base=request.host_url,
          logado_portal=logado_portal,
          erro=erro,
      )
    except:
      return (
          f"O sistema tentou abrir o portal correspondente a '{faculdade_slug}',"
          " mas o arquivo do template não foi encontrado na pasta 'portais'.",
          404,
      )

@app.route('/validacao/<faculdade_slug>/<identificador>')
def validacao_qr_code(faculdade_slug, identificador):
  id_limpo = normalizar_cpf(identificador)
  conn = get_db_connection()
  aluno = None
  try:
    aluno = conn.execute('SELECT * FROM alunos WHERE cpf = ? OR matricula = ?', (id_limpo, identificador)).fetchone()
  except Exception:
      pass
  finally:
    conn.close()
    
  if not aluno:
    return (
        'Aluno não encontrado. Verifique se o CPF ou matrícula existe no banco de dados.',
        404,
    )

  slug = aluno['faculdade_slug'] if aluno['faculdade_slug'] else faculdade_slug

  try:
    return render_template(
        f'portais/portal_{slug}.html',
        aluno=aluno,
        url_base=request.host_url,
        logado_portal=True,
        erro=None,
    )
  except Exception:
    try:
      return render_template(
          f'portais/{slug}.html',
          aluno=aluno,
          url_base=request.host_url,
          logado_portal=True,
          erro=None,
      )
    except:
      return 'Arquivo de portal não encontrado na pasta templates/portais.', 404

@app.route('/visualizar_qrcode/<cpf>')
def visualizar_qrcode(cpf):
  cpf = normalizar_cpf(cpf)
  conn = get_db_connection()
  aluno = None
  try:
    aluno = conn.execute('SELECT * FROM alunos WHERE cpf = ?', (cpf,)).fetchone()
  except Exception:
      pass
  finally:
    conn.close()
    
  if not aluno:
    return 'Aluno não encontrado.', 404

  slug = aluno['faculdade_slug'] if aluno['faculdade_slug'] else 'unip'
  dominio_alvo = obter_url_base_faculdade(slug)
  return redirect(f'{dominio_alvo}/validacao/{slug}/{cpf}', code=301)

@app.route('/consulta_xml', methods=['GET', 'POST'])
def consulta_xml():
  aluno = None
  erro = None
  if request.method == 'POST':
    arquivo = request.files.get('arquivo_xml')
    if arquivo and arquivo.filename:
      nome_completo = secure_filename(arquivo.filename)
      nome_base = os.path.splitext(nome_completo)[0]
      busca_completa = f'%{nome_completo}%'
      busca_base = f'%{nome_base}%'

      conn = get_db_connection()
      try:
        aluno = conn.execute(
            '''
                  SELECT * FROM alunos 
                  WHERE diploma_frente LIKE ? OR diploma_verso LIKE ? OR historico LIKE ? OR certificado LIKE ?
                     OR diploma_frente LIKE ? OR diploma_verso LIKE ? OR historico LIKE ? OR certificado LIKE ?
              ''',
            (
                busca_completa,
                busca_completa,
                busca_completa,
                busca_completa,
                busca_base,
                busca_base,
                busca_base,
                busca_base,
            ),
        ).fetchone()
      except Exception:
          pass
      finally:
        conn.close()

      if not aluno:
        erro = 'Arquivo não reconhecido ou aluno não cadastrado com este documento.'
    else:
      erro = 'Nenhum arquivo selecionado.'
  return render_template('consulta_xml.html', aluno=aluno, erro=erro)

@app.route('/consulta/xml/<cpf>')
def consulta_xml_direta(cpf):
  cpf = normalizar_cpf(cpf)
  conn = get_db_connection()
  aluno = None
  try:
    aluno = conn.execute(
        'SELECT * FROM alunos WHERE cpf = ?', (cpf,)
    ).fetchone()
  except Exception:
      pass
  finally:
    conn.close()
    
  if not aluno:
    return 'Cadastro não encontrado.', 404
  return render_template('consulta_xml.html', aluno=aluno, erro=None)

@app.route('/imprensanacional/consulta/<cpf>')
def imprensanacional_consulta(cpf):
  cpf = normalizar_cpf(cpf)
  conn = get_db_connection()
  aluno = None
  try:
    aluno = conn.execute(
        'SELECT * FROM alunos WHERE cpf = ?', (cpf,)
    ).fetchone()
  except Exception:
      pass
  finally:
    conn.close()
    
  if not aluno:
    return 'Candidato não encontrado.', 404
  return render_template(
      'consulta_imprensanacional.html',
      aluno=aluno,
      url_base=DOMINIOS_MAPA['dou'] + '/',
  )

@app.route('/imprensanacional/busca')
def imprensanacional_busca():
  termo = request.args.get('q', '')
  return (
      "<div style='font-family: Arial; padding: 50px;'><h2>Pesquisa DOU:"
      f' {termo}</h2></div>'
  )

@app.route('/download/<filename>')
def download_file(filename):
  baixar = request.args.get('baixar') == '1'
  return send_from_directory(
      app.config['UPLOAD_FOLDER'], secure_filename(filename), as_attachment=baixar
  )

@app.route('/visualizar_documento/<int:aluno_id>/<tipo_doc>')
def visualizar_documento(aluno_id, tipo_doc):
  conn = get_db_connection()
  aluno = None
  try:
    aluno = conn.execute('SELECT * FROM alunos WHERE id = ?', (aluno_id,)).fetchone()
  except Exception:
      pass
  finally:
    conn.close()
    
  if not aluno:
    return 'Aluno não encontrado.', 404
    
  filenames_raw = ''
  titulo_doc = ''
  if tipo_doc == 'certificado':
    filenames_raw, titulo_doc = aluno['certificado'], 'Certificado de Conclusão'
  elif tipo_doc == 'historico':
    filenames_raw, titulo_doc = aluno['historico'], 'Histórico Escolar'
  elif tipo_doc == 'outros':
    filenames_raw, titulo_doc = aluno['outros_docs'], 'Outros'
  else:
    return abort(400)
    
  filenames = [
      secure_filename(f) for f in (filenames_raw or '').split('|') if f
  ]
  return render_template(
      'visualizar_combinado.html',
      aluno=aluno,
      filenames=filenames,
      titulo_doc=titulo_doc,
  )

@app.route('/conselho_oab/<int:id>')
def conselho_oab(id):
  conn = get_db_connection()
  aluno = None
  try:
    aluno = conn.execute('SELECT * FROM alunos WHERE id = ?', (id,)).fetchone()
  except Exception:
      pass
  finally:
    conn.close()
    
  if not aluno:
    return 'Aluno não encontrado.', 404
  return render_template('conselhos/conselho_oab.html', aluno=aluno)

@app.route('/conselho_confea/<int:id>')
def conselho_confea(id):
  conn = get_db_connection()
  aluno = None
  try:
    aluno = conn.execute('SELECT * FROM alunos WHERE id = ?', (id,)).fetchone()
  except Exception:
      pass
  finally:
    conn.close()
    
  if not aluno:
    return 'Profissional não encontrado.', 404
  return render_template('conselhos/conselho_confea.html', aluno=aluno)

@app.route('/gerar_posse/<int:id>')
def gerar_posse(id):
  conn = get_db_connection()
  aluno = None
  try:
    aluno = conn.execute('SELECT * FROM alunos WHERE id = ?', (id,)).fetchone()
  except Exception:
      pass
  finally:
    conn.close()
    
  if not aluno:
    return 'Candidato não encontrado.', 404
  return render_template(
      'termo_posse.html',
      aluno=aluno,
      p_num=random.randint(10, 999),
      p_ano=random.randint(2023, 2026),
  )

@app.route('/gerar_exercicio/<int:id>')
def gerar_exercicio(id):
  conn = get_db_connection()
  aluno = None
  try:
    aluno = conn.execute('SELECT * FROM alunos WHERE id = ?', (id,)).fetchone()
  except Exception:
      pass
  finally:
    conn.close()
    
  if not aluno:
    return 'Candidato não encontrado.', 404
  return render_template('termo_exercicio.html', aluno=aluno)

if __name__ == '__main__':
  porta = int(os.environ.get('PORT', 5000))
  app.run(host='0.0.0.0', port=porta, debug=False)