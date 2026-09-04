from datetime import timedelta
from functools import wraps
import os
import random
import urllib.parse
import urllib.request
from flask import (
    Flask,
    abort,
    jsonify,
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
import requests

# --- BIBLIOTECAS DO POSTGRESQL ---
import psycopg2
from psycopg2.extras import DictCursor

app = Flask(__name__)

# ==========================================
# CONFIGURAÇÕES DE SEGURANÇA SÊNIOR
# ==========================================
app.secret_key = os.environ.get(
    'SECRET_KEY', 'kR9#m2Pq!v8Z$xL5@nW3*yT7^c4F1bN0'
)

csrf = CSRFProtect(app)

EM_PRODUCAO = 'RENDER' in os.environ

app.config['SESSION_COOKIE_SECURE'] = EM_PRODUCAO
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.wsgi_app = ProxyFix(
    app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
)

UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
  os.makedirs(UPLOAD_FOLDER)

ADMIN_USUARIO = os.environ.get('ADMIN_USUARIO', 'admn')
ADMIN_SENHA = os.environ.get('ADMIN_SENHA', '992136520Fe.')

# ==========================================
# MAPEAMENTO DE DOMÍNIOS
# ==========================================
DOMINIOS_MAPA = {
    'painel': 'https://secretariaderegistrosgovbr.com',
    'consulta_xml': 'https://verificadordiplomadigitalmecgovbr.com',
    'dou': 'https://govbr-mec.com',
    'cna': 'https://cna-oab-org-br.com',
    'estacio': 'https://sia-estaciobr.com',
    'puc': 'https://sol-puc-goias-edubr.com',
    'unip': 'https://unip-braluno.com',
}

def obter_url_base_faculdade(slug):
  if slug == 'unip':
    return DOMINIOS_MAPA['unip']
  elif slug == 'sia_estacio_br':
    return DOMINIOS_MAPA['estacio']
  elif slug == 'puc_go':
    return DOMINIOS_MAPA['puc']
  else:
    return DOMINIOS_MAPA['puc']

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

# ==========================================
# BANCO DE DADOS DEFINITIVO: POSTGRESQL NUVEM
# ==========================================
DB_URL = os.environ.get('DATABASE_URL')

if not DB_URL:
  raise RuntimeError(
      "ERRO: A variavel de ambiente DATABASE_URL nao esta configurada no Render. "
      "Va em Environment do seu Web Service e adicione DATABASE_URL apontando "
      "para a Internal Database URL do seu banco PostgreSQL."
  )

# Render fornece a URL comecando com 'postgres://', mas o psycopg2 mais novo
# espera 'postgresql://'. Esta linha corrige isso automaticamente.
if DB_URL.startswith('postgres://'):
  DB_URL = DB_URL.replace('postgres://', 'postgresql://', 1)

class PostgresConnWrapper:
    def _init_(self):
        try:
            self.conn = psycopg2.connect(DB_URL, sslmode='require')
            self.conn.autocommit = False
        except Exception as e:
            print(
                f"[ERRO CONEXAO POSTGRES] {type(e)._name_}: {e}",
                flush=True,
            )
            raise

    def execute(self, query, params=()):
        cur = self.conn.cursor(cursor_factory=DictCursor)
        pg_query = query.replace('?', '%s')
        cur.execute(pg_query, params)
        return cur

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.close()

def get_db_connection():
    return PostgresConnWrapper()

def init_db():
  conn = get_db_connection()
  
  conn.execute('''
        CREATE TABLE IF NOT EXISTS alunos (
            id SERIAL PRIMARY KEY,
            nome TEXT, cpf TEXT, rg TEXT, orgao_rg TEXT, data_expedicao TEXT,
            data_nascimento TEXT, naturalidade TEXT, filiacao TEXT, endereco TEXT, foto TEXT,
            tipo_curso TEXT, curso TEXT, grau_academico TEXT, instituicao_ensino TEXT, 
            data_inicio TEXT, data_conclusao TEXT, carga_horaria TEXT, matricula TEXT, 
            registro_validacao TEXT, gerar_qrcode TEXT,
            diploma_frente TEXT, diploma_verso TEXT,
            certificado TEXT, historico TEXT, outros_docs TEXT,
            edital_concurso TEXT, data_homologacao TEXT, dados_nomeacao TEXT, data_posse TEXT, data_exercicio TEXT,
            esfera_concurso TEXT, local_esfera TEXT, orgao TEXT, numero_registro TEXT, uf_registro TEXT, faculdade_slug TEXT
        )
    ''')

  conn.execute('''
        CREATE TABLE IF NOT EXISTS equipe (
            id SERIAL PRIMARY KEY,
            nome TEXT, cargo TEXT, usuario TEXT, senha TEXT, status_acesso TEXT
        )
    ''')

  conn.commit()
  conn.close()

init_db()

# ==========================================
# FUNÇÕES DE UPLOAD
# ==========================================
def salvar_arquivo(file_storage):
  if file_storage and file_storage.filename != '':
    filename = secure_filename(file_storage.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file_storage.save(filepath)
    return filename
  return ''

def salvar_multiplos_arquivos(file_storage_list, antigos=''):
  nomes_salvos = []
  for f in file_storage_list:
    if f and f.filename != '':
      filename = secure_filename(f.filename)
      filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
      f.save(filepath)
      nomes_salvos.append(filename)
  if nomes_salvos:
    return '|'.join(nomes_salvos)
  return antigos

# ==========================================
# ROTEADOR DE DOMÍNIOS E SEGURANÇA
# ==========================================
@app.before_request
def travar_dominios_e_autenticacao():
  session.modified = True

  if request.endpoint == 'static':
    return

  host = request.host.lower()

  if 'verificadordiplomadigitalmecgovbr' in host:
    rotas_xml = ['consulta_xml', 'consulta_xml_direta']
    if request.endpoint not in rotas_xml:
      return redirect(url_for('consulta_xml'))

  elif 'govbr-mec' in host:
    rotas_dou = ['imprensanacional_busca', 'imprensanacional_consulta']
    if request.endpoint not in rotas_dou:
      return redirect(url_for('imprensanacional_busca'))

  elif 'cna-oab-org-br' in host:
    if request.endpoint != 'conselho_oab':
      return "Acesso restrito. Utilize o link com o ID direto da consulta CNA.", 403

  elif 'sia-estaciobr' in host or 'sol-puc-goias-edubr' in host or 'unip-braluno' in host:
    rotas_portais = [
        'portal_do_aluno_publico', 'validacao_qr_code', 
        'visualizar_qrcode', 'visualizar_documento', 'download_file'
    ]
    if request.endpoint not in rotas_portais:
      return "Acesso restrito ao portal do aluno. Utilize o link oficial do seu QR Code ou Matrícula.", 403

  else:
    rotas_livres = [
        'login', 'solicitar_acesso', 'portal_do_aluno_publico', 'validacao_qr_code', 
        'consulta_xml', 'consulta_xml_direta', 'imprensanacional_consulta', 'imprensanacional_busca', 
        'download_file', 'visualizar_documento', 'conselho_oab', 'visualizar_qrcode', 'gerar_posse', 'gerar_exercicio'
    ]
    if request.endpoint not in rotas_livres and not session.get('logado'):
      return redirect(url_for('login'))

def somente_admn(f):
  @wraps(f)
  def wrapper(*args, **kwargs):
    if session.get('cargo') != 'admn':
      abort(403)
    return f(*args, **kwargs)
  return wrapper

@app.route('/login', methods=['GET', 'POST'])
def login():
  if request.method == 'POST':
    turnstile_token = request.form.get('cf-turnstile-response')
    user_ip = request.remote_addr

    verify_response = requests.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', data={
        'secret': '0x4AAAAAAa9xhYF1C8HiB95Stt3aokG08',
        'response': turnstile_token,
        'remoteip': user_ip
    })
    
    result = verify_response.json()

    if not result.get('success'):
      return render_template(
          'login.html', erro='Confirmação de segurança (Turnstile) falhou. Tente novamente.'
      )

    usuario_digitado = request.form.get('usuario', '').strip()
    senha_digitada = request.form.get('senha', '').strip()

    if usuario_digitado == ADMIN_USUARIO and senha_digitada == ADMIN_SENHA:
      session.permanent = True
      session['logado'] = True
      session['cargo'] = 'admn'
      return redirect(url_for('index'))

    conn = get_db_connection()
    membro = conn.execute(
        "SELECT * FROM equipe WHERE usuario = ? AND status_acesso = 'Ativo'",
        (usuario_digitado,),
    ).fetchone()
    conn.close()

    if membro and check_password_hash(membro['senha'], senha_digitada):
      session.permanent = True
      session['logado'] = True
      session['cargo'] = 'secretario'
      return redirect(url_for('index'))

    return render_template(
        'login.html', erro='Credenciais inválidas ou acesso pendente.'
    )
  return render_template('login.html')

@app.route('/logout')
def logout():
  session.clear()
  return redirect(url_for('login'))

@app.route('/solicitar_acesso', methods=['GET', 'POST'])
def solicitar_acesso():
  sucesso = None
  erro = None
  if request.method == 'POST':
    nome = request.form.get('nome')
    cargo = request.form.get('cargo')
    usuario = request.form.get('usuario', '').strip()
    senha = request.form.get('senha')
    conn = get_db_connection()
    existente = conn.execute(
        'SELECT * FROM equipe WHERE usuario = ?', (usuario,)
    ).fetchone()
    if existente:
      erro = 'Este usuário já está sendo utilizado. Escolha outro.'
    else:
      hash_senha = generate_password_hash(senha, method='pbkdf2:sha256')
      conn.execute(
          'INSERT INTO equipe (nome, cargo, usuario, senha, status_acesso)'
          ' VALUES (?, ?, ?, ?, ?)',
          (nome, cargo, usuario, hash_senha, 'Pendente'),
      )
      conn.commit()
      sucesso = 'Solicitação enviada! Aguarde a liberação do administrador.'
    conn.close()
  return render_template('solicitar_acesso.html', sucesso=sucesso, erro=erro)

@app.route('/aprovar_equipe/<int:id>', methods=['POST'])
@somente_admn
def aprovar_equipe(id):
  conn = get_db_connection()
  conn.execute(
      "UPDATE equipe SET status_acesso = 'Ativo' WHERE id = ?", (id,)
  )
  conn.commit()
  conn.close()
  return redirect(url_for('index'))

@app.route('/remover_equipe/<int:id>', methods=['POST'])
@somente_admn
def remover_equipe(id):
  conn = get_db_connection()
  conn.execute('DELETE FROM equipe WHERE id = ?', (id,))
  conn.commit()
  conn.close()
  return redirect(url_for('index'))

# ==========================================
# ROTAS DO SISTEMA INTERNO
# ==========================================
@app.route('/')
def index():
  conn = get_db_connection()
  total_alunos = conn.execute('SELECT COUNT(*) FROM alunos').fetchone()[0]
  equipe_ativa = conn.execute(
      "SELECT * FROM equipe WHERE status_acesso = 'Ativo'"
  ).fetchall()
  equipe_pendente = conn.execute(
      "SELECT * FROM equipe WHERE status_acesso = 'Pendente'"
  ).fetchall()
  conn.close()
  return render_template(
      'index.html', total=total_alunos, ativos=equipe_ativa, pendentes=equipe_pendente
  )

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

    conn = get_db_connection()
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
            dados['nome'], dados['cpf'], dados['rg'], dados['orgao_rg'], dados['data_expedicao'],
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
            dados.get('uf_registro', ''), dados.get('faculdade_slug', ''),
        ),
    )
    conn.commit()
    conn.close()

    return redirect(url_for('cadastro'))
  return render_template('cadastro.html')

@app.route('/alterar', methods=['GET', 'POST'])
def alterar():
  alunos = []
  if request.method == 'POST':
    termo = request.form.get('termo', '')
    conn = get_db_connection()
    alunos = conn.execute(
        'SELECT * FROM alunos WHERE nome LIKE ? OR cpf = ?',
        ('%' + termo + '%', termo),
    ).fetchall()
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
            dados['nome'], dados['cpf'], dados['rg'], dados['orgao_rg'], dados['data_expedicao'],
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
            dados.get('uf_registro', ''), dados.get('faculdade_slug', ''),
            id,
        ),
    )
    conn.commit()
    conn.close()

    return redirect(url_for('alterar'))
  aluno = conn.execute('SELECT * FROM alunos WHERE id = ?', (id,)).fetchone()
  conn.close()
  return render_template('editar.html', aluno=aluno)

@app.route('/excluir', methods=['GET', 'POST'])
def excluir():
  alunos = []
  if request.method == 'POST':
    termo = request.form.get('termo', '')
    conn = get_db_connection()
    alunos = conn.execute(
        'SELECT * FROM alunos WHERE nome LIKE ? OR cpf = ?',
        ('%' + termo + '%', termo),
    ).fetchall()
    conn.close()
  return render_template('excluir.html', alunos=alunos)

@app.route('/deletar/<int:id>', methods=['POST'])
def deletar(id):
  conn = get_db_connection()
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
  conn.execute('DELETE FROM alunos')
  conn.commit()
  conn.close()
  return redirect(url_for('excluir'))

@app.route('/informacoes/<tipo>', methods=['GET', 'POST'])
def informacoes(tipo):
  alunos = []
  if tipo == 'graduacao':
    titulo = 'Dossiê de Graduações'
    filtro_sql = "tipo_curso IN ('Bacharelado', 'Licenciatura', 'Tecnologia')"
  else:
    titulo = 'Dossiê de Concursos'
    filtro_sql = "tipo_curso IN ('Concurso Público', 'Concurso Privado')"

  if request.method == 'POST':
    termo = request.form.get('termo', '')
    conn = get_db_connection()
    alunos = conn.execute(
        f'''
            SELECT * FROM alunos 
            WHERE (nome LIKE ? OR cpf = ?) AND ({filtro_sql})
        ''',
        ('%' + termo + '%', termo),
    ).fetchall()
    conn.close()
  return render_template(
      'informacoes.html', alunos=alunos, tipo=tipo, titulo=titulo
  )

@app.route('/painel_aluno/<int:id>')
def painel_aluno(id):
  conn = get_db_connection()
  aluno = conn.execute('SELECT * FROM alunos WHERE id = ?', (id,)).fetchone()
  conn.close()
  if not aluno:
    return 'Aluno não encontrado.', 404

  slug = aluno['faculdade_slug'] if aluno['faculdade_slug'] else 'puc_go'
  dominio_faculdade = obter_url_base_faculdade(slug)

  url_base_custom = {
      'painel': DOMINIOS_MAPA['painel'] + '/',
      'xml': DOMINIOS_MAPA['consulta_xml'] + '/',
      'dou': DOMINIOS_MAPA['dou'] + '/',
      'cna': DOMINIOS_MAPA['cna'] + '/',
      'portal': dominio_faculdade + '/',
      'validacao': f'{dominio_faculdade}/validacao/{slug}/',
  }

  return render_template('painel_aluno.html', aluno=aluno, url_base=url_base_custom)

# ==========================================
# ROTAS PÚBLICAS
# ==========================================
@app.route('/portal_aluno/<matricula>', methods=['GET', 'POST'])
def portal_do_aluno_publico(matricula):
  conn = get_db_connection()
  aluno = conn.execute(
      'SELECT * FROM alunos WHERE matricula = ?', (matricula,)
  ).fetchone()
  conn.close()
  if not aluno:
    return 'Matrícula não encontrada. Verifique o link.', 404

  faculdade_slug = (
      aluno['faculdade_slug'] if aluno['faculdade_slug'] else 'puc_go'
  )

  logado_portal = False
  erro = None

  if request.method == 'POST':
    senha_digitada = ''.join(
        filter(str.isdigit, request.form.get('senha', ''))
    )
    cpf_banco = ''.join(filter(str.isdigit, str(aluno['cpf'])))

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
  except Exception as e:
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

@app.route('/validacao/<faculdade_slug>/<cpf>')
def validacao_qr_code(faculdade_slug, cpf):
  conn = get_db_connection()
  aluno = conn.execute('SELECT * FROM alunos WHERE cpf = ?', (cpf,)).fetchone()
  conn.close()
  if not aluno:
    return (
        'Aluno não encontrado. Verifique se o CPF existe no banco de dados.',
        404,
    )

  slug = aluno['faculdade_slug'] if aluno['faculdade_slug'] else faculdade_slug

  try:
    return render_template(
        f'portais/portal_{slug}.html',
        aluno=aluno,
        url_base=request.host_url,
        logado_portal=False,
        erro=None,
    )
  except Exception as e:
    try:
      return render_template(
          f'portais/{slug}.html',
          aluno=aluno,
          url_base=request.host_url,
          logado_portal=False,
          erro=None,
      )
    except:
      return 'Arquivo de portal não encontrado na pasta templates/portais.', 404

@app.route('/visualizar_qrcode/<cpf>')
def visualizar_qrcode(cpf):
  conn = get_db_connection()
  aluno = conn.execute('SELECT * FROM alunos WHERE cpf = ?', (cpf,)).fetchone()
  conn.close()
  if not aluno:
    return 'Aluno não encontrado.', 404

  slug = aluno['faculdade_slug'] if aluno['faculdade_slug'] else 'puc_go'
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
      conn.close()

      if not aluno:
        erro = (
            'Arquivo não reconhecido ou aluno não cadastrado com este'
            ' documento.'
        )
    else:
      erro = 'Nenhum arquivo selecionado.'
  return render_template('consulta_xml.html', aluno=aluno, erro=erro)

@app.route('/consulta/xml/<matricula>')
def consulta_xml_direta(matricula):
  conn = get_db_connection()
  aluno = conn.execute(
      'SELECT * FROM alunos WHERE matricula = ?', (matricula,)
  ).fetchone()
  conn.close()
  if not aluno:
    return 'Matrícula não encontrada.', 404
  return render_template('consulta_xml.html', aluno=aluno, erro=None)

@app.route('/imprensanacional/consulta/<matricula>')
def imprensanacional_consulta(matricula):
  conn = get_db_connection()
  aluno = conn.execute(
      'SELECT * FROM alunos WHERE matricula = ?', (matricula,)
  ).fetchone()
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
  return send_from_directory(
      app.config['UPLOAD_FOLDER'], secure_filename(filename), as_attachment=True
  )

@app.route('/visualizar_documento/<int:aluno_id>/<tipo_doc>')
def visualizar_documento(aluno_id, tipo_doc):
  conn = get_db_connection()
  aluno = conn.execute('SELECT * FROM alunos WHERE id = ?', (aluno_id,)).fetchone()
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
  aluno = conn.execute('SELECT * FROM alunos WHERE id = ?', (id,)).fetchone()
  conn.close()
  if not aluno:
    return 'Aluno não encontrado.', 404
  return render_template('conselhos/conselho_oab.html', aluno=aluno)

@app.route('/gerar_posse/<int:id>')
def gerar_posse(id):
  conn = get_db_connection()
  aluno = conn.execute('SELECT * FROM alunos WHERE id = ?', (id,)).fetchone()
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
  aluno = conn.execute('SELECT * FROM alunos WHERE id = ?', (id,)).fetchone()
  conn.close()
  if not aluno:
    return 'Candidato não encontrado.', 404
  return render_template('termo_exercicio.html', aluno=aluno)

if __name__ == '__main__':
  app.run(debug=True)