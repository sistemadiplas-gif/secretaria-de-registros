import os
import sqlite3
import psycopg2
from psycopg2.extras import DictCursor

DB_URL = os.environ.get('DATABASE_URL')

if DB_URL and DB_URL.startswith('postgres://'):
  DB_URL = DB_URL.replace('postgres://', 'postgresql://', 1)

class DBConnWrapper:
    def __init__(self):
        self.usa_postgres = bool(DB_URL)
        if self.usa_postgres:
            try:
                self.conn = psycopg2.connect(DB_URL, sslmode='require')
                self.conn.autocommit = False
            except Exception as e:
                print(f"[ERRO CONEXAO POSTGRES] {type(e).__name__}: {e}", flush=True)
                raise
        else:
            self.conn = sqlite3.connect('database.db', check_same_thread=False)
            self.conn.row_factory = sqlite3.Row

    def execute(self, query, params=()):
        if self.usa_postgres:
            cur = self.conn.cursor(cursor_factory=DictCursor)
            pg_query = query.replace('?', '%s')
            cur.execute(pg_query, params)
            return cur
        else:
            cur = self.conn.cursor()
            sqlite_query = query.replace('SERIAL PRIMARY KEY', 'INTEGER PRIMARY KEY AUTOINCREMENT')
            cur.execute(sqlite_query, params)
            return cur

    def commit(self):
        self.conn.commit()

    def close(self):
        if self.conn:
            self.conn.close()

def get_db_connection():
    return DBConnWrapper()

def init_db():
  conn = get_db_connection()
  try:
      conn.execute('''
            CREATE TABLE IF NOT EXISTS alunos (
                id SERIAL PRIMARY KEY, nome TEXT, cpf TEXT, rg TEXT, orgao_rg TEXT, data_expedicao TEXT,
                data_nascimento TEXT, naturalidade TEXT, filiacao TEXT, endereco TEXT, foto TEXT,
                tipo_curso TEXT, curso TEXT, grau_academico TEXT, instituicao_ensino TEXT, 
                data_inicio TEXT, data_conclusao TEXT, carga_horaria TEXT, matricula TEXT, 
                registro_validacao TEXT, gerar_qrcode TEXT, diploma_frente TEXT, diploma_verso TEXT,
                certificado TEXT, historico TEXT, outros_docs TEXT, edital_concurso TEXT, data_homologacao TEXT, 
                dados_nomeacao TEXT, data_posse TEXT, data_exercicio TEXT, esfera_concurso TEXT, local_esfera TEXT, 
                orgao TEXT, numero_registro TEXT, uf_registro TEXT, faculdade_slug TEXT
            )
        ''')

      conn.execute('''
            CREATE TABLE IF NOT EXISTS equipe (
                id SERIAL PRIMARY KEY, nome TEXT, cargo TEXT, usuario TEXT, senha TEXT, status_acesso TEXT
            )
        ''')
      conn.commit()
  finally:
      conn.close()