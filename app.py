"""
=======================================================
LILICA VENDAS — Backend Flask + MySQL (Railway)
=======================================================
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import mysql.connector
import hashlib
import hmac
import os as _os
import jwt
import os
import logging
from datetime import datetime, timedelta
from functools import wraps

# ─────────────────────────────────────────────────────
# CONFIGURAÇÃO DO SERVIDOR
# ─────────────────────────────────────────────────────
app = Flask(__name__, static_folder='static')

# CORS restrito ao domínio do Netlify
NETLIFY_URL = os.environ.get('NETLIFY_URL', '*')
CORS(app, origins=[NETLIFY_URL] if NETLIFY_URL != '*' else '*')

# Logs
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────
# VARIÁVEIS DE AMBIENTE (configuradas no Railway)
# ─────────────────────────────────────────────────────
DB_CONFIG = {
    "host":     os.environ.get("MYSQLHOST"),
    "port":     int(os.environ.get("MYSQLPORT", 3306)),
    "user":     os.environ.get("MYSQLUSER"),
    "password": os.environ.get("MYSQLPASSWORD"),
    "database": os.environ.get("MYSQLDATABASE", "railway")
}

# Chave secreta para JWT — configure no Railway: JWT_SECRET=SuaChaveSecreta123
JWT_SECRET = os.environ.get("JWT_SECRET", "lilica_jwt_secret_2025")
JWT_EXPIRACAO_HORAS = 8

# Rate limiting manual (tentativas de login por IP)
MAX_TENTATIVAS = 5
JANELA_MINUTOS = 10

# ─────────────────────────────────────────────────────
# CONEXÃO COM O BANCO
# ─────────────────────────────────────────────────────
def conectar():
    """Abre e retorna uma conexão com o MySQL"""
    return mysql.connector.connect(**DB_CONFIG)


# ─────────────────────────────────────────────────────
# SEGURANÇA — bcrypt para senhas
# ─────────────────────────────────────────────────────
def hash_senha(senha):
    """Gera hash PBKDF2-SHA256 da senha com salt aleatório"""
    salt = _os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', senha.encode('utf-8'), salt, 310000)
    return salt.hex() + ':' + key.hex()

def verificar_senha(senha, hash_salvo):
    """Verifica se a senha bate com o hash salvo"""
    try:
        # Suporte a hashes bcrypt antigos (começam com $2b$)
        if hash_salvo.startswith('$2b$') or hash_salvo.startswith('$2a$'):
            import bcrypt as _bcrypt
            return _bcrypt.checkpw(senha.encode('utf-8'), hash_salvo.encode('utf-8'))
        # Hash novo no formato salt:key
        salt_hex, key_hex = hash_salvo.split(':')
        salt = bytes.fromhex(salt_hex)
        key = hashlib.pbkdf2_hmac('sha256', senha.encode('utf-8'), salt, 310000)
        return hmac.compare_digest(key.hex(), key_hex)
    except Exception:
        return False


# ─────────────────────────────────────────────────────
# JWT — gerar e verificar tokens
# ─────────────────────────────────────────────────────
def gerar_token(usuario_id, nome, perfil):
    """Gera um token JWT com expiração de 8 horas"""
    payload = {
        'id':     usuario_id,
        'nome':   nome,
        'perfil': perfil,
        'exp':    datetime.utcnow() + timedelta(hours=JWT_EXPIRACAO_HORAS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verificar_token(token):
    """Verifica e decodifica o token JWT"""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# ─────────────────────────────────────────────────────
# DECORATOR — protege rotas com JWT
# ─────────────────────────────────────────────────────
def requer_autenticacao(f):
    """Decorator: verifica JWT antes de executar a rota"""
    @wraps(f)
    def decorada(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({'ok': False, 'erro': 'Token não fornecido'}), 401
        token = auth.replace('Bearer ', '')
        payload = verificar_token(token)
        if not payload:
            return jsonify({'ok': False, 'erro': 'Token inválido ou expirado'}), 401
        request.usuario = payload
        return f(*args, **kwargs)
    return decorada

def requer_admin(f):
    """Decorator: verifica JWT e se o usuário é administrador"""
    @wraps(f)
    def decorada(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({'ok': False, 'erro': 'Token não fornecido'}), 401
        token = auth.replace('Bearer ', '')
        payload = verificar_token(token)
        if not payload:
            return jsonify({'ok': False, 'erro': 'Token inválido ou expirado'}), 401
        if payload.get('perfil') != 'admin':
            return jsonify({'ok': False, 'erro': 'Acesso restrito a administradores'}), 403
        request.usuario = payload
        return f(*args, **kwargs)
    return decorada


# ─────────────────────────────────────────────────────
# RATE LIMITING — proteção contra brute force no login
# ─────────────────────────────────────────────────────
def verificar_rate_limit(usuario, ip):
    """Verifica se o IP/usuário excedeu o limite de tentativas"""
    con = conectar()
    cur = con.cursor(dictionary=True)
    try:
        janela = datetime.utcnow() - timedelta(minutes=JANELA_MINUTOS)
        cur.execute(
            "SELECT COUNT(*) AS total FROM tentativas_login"
            " WHERE (usuario=%s OR ip=%s) AND sucesso=FALSE AND created_at > %s",
            (usuario, ip, janela)
        )
        total = cur.fetchone()['total']
        return total >= MAX_TENTATIVAS
    finally:
        con.close()

def registrar_tentativa(usuario, ip, sucesso):
    """Registra uma tentativa de login no banco"""
    con = conectar()
    cur = con.cursor()
    try:
        cur.execute(
            "INSERT INTO tentativas_login (usuario, ip, sucesso) VALUES (%s, %s, %s)",
            (usuario, ip, sucesso)
        )
        con.commit()
    except Exception as e:
        logger.error(f"Erro ao registrar tentativa: {e}")
    finally:
        con.close()


# ─────────────────────────────────────────────────────
# FUNÇÃO AUXILIAR — inserir dados relacionados do cliente
# ─────────────────────────────────────────────────────
def _inserir_relacionados(cur, cliente_id, dados):
    """
    Insere produtos de interesse, encomendas, compras e pagamentos.
    Usada em criar_cliente() e atualizar_cliente() para evitar duplicação.
    """
    # Produtos de interesse
    for p in dados.get('produtos', []):
        nome = (p.get('nome') or '').strip()
        if nome and len(nome) <= 150:
            cur.execute(
                "INSERT INTO produtos_interesse (cliente_id, nome, quantidade)"
                " VALUES (%s, %s, %s)",
                (cliente_id, nome, (p.get('qtd') or '')[:50])
            )

    # Encomendas
    for e in dados.get('encomendas', []):
        produto = (e.get('produto') or '').strip()
        if produto and len(produto) <= 150:
            status = e.get('status', 'Pendente')
            if status not in ('Pendente', 'Entregue'):
                status = 'Pendente'
            cur.execute(
                "INSERT INTO encomendas (cliente_id, produto, quantidade, status)"
                " VALUES (%s, %s, %s, %s)",
                (cliente_id, produto, (e.get('qtd') or '')[:50], status)
            )

    # Compras e pagamentos
    for c in dados.get('compras', []):
        try:
            valor_total = float(c.get('total') or 0)
            custo       = float(c.get('custo')  or 0)
        except (ValueError, TypeError):
            valor_total = 0
            custo       = 0

        cur.execute(
            "INSERT INTO compras"
            " (cliente_id, descricao, data, valor_total, fornecedor, custo, repassado)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (
                cliente_id,
                (c.get('desc') or '')[:200],
                c.get('data') or None,
                valor_total,
                (c.get('fornecedor') or '')[:100],
                custo,
                bool(c.get('repassado', False))
            )
        )
        compra_id = cur.lastrowid

        for pg in c.get('pagamentos', []):
            try:
                valor_pg = float(pg.get('valor') or 0)
            except (ValueError, TypeError):
                valor_pg = 0

            cur.execute(
                "INSERT INTO pagamentos (compra_id, data, valor, forma, banco)"
                " VALUES (%s, %s, %s, %s, %s)",
                (
                    compra_id,
                    pg.get('data') or None,
                    valor_pg,
                    (pg.get('forma') or '')[:50],
                    (pg.get('banco') or '')[:100]
                )
            )


# ─────────────────────────────────────────────────────
# SERVIR O FRONTEND
# ─────────────────────────────────────────────────────
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/debug/login', methods=['POST'])
def debug_login():
    """Rota de debug para testar login passo a passo"""
    d = request.json or {}
    usuario = (d.get('usuario') or '').strip().lower()
    senha   = (d.get('senha')   or '').strip()
    
    resultado = {
        'usuario_recebido': usuario,
        'senha_recebida': bool(senha),
        'passos': []
    }
    
    con = conectar()
    cur = con.cursor(dictionary=True)
    try:
        # Passo 1: buscar usuário
        cur.execute("SELECT id, nome, usuario, senha_hash, perfil, ativo FROM usuarios WHERE usuario = %s", (usuario,))
        user = cur.fetchone()
        
        if not user:
            resultado['passos'].append('ERRO: usuario nao encontrado no banco')
            return jsonify(resultado)
        
        resultado['passos'].append(f'OK: usuario encontrado - id={user["id"]} ativo={user["ativo"]}')
        resultado['hash_formato'] = user['senha_hash'][:30] + '...'
        resultado['hash_tem_dois_pontos'] = ':' in user['senha_hash']
        resultado['hash_bcrypt'] = user['senha_hash'].startswith('$2b$')
        
        # Passo 2: verificar senha
        ok = verificar_senha(senha, user['senha_hash'])
        resultado['senha_ok'] = ok
        resultado['passos'].append(f'Verificacao senha: {ok}')
        
        return jsonify(resultado)
    except Exception as e:
        resultado['erro'] = str(e)
        return jsonify(resultado)
    finally:
        con.close()




# ─────────────────────────────────────────────────────
# POST /login — autenticação com JWT
# ─────────────────────────────────────────────────────
@app.route('/login', methods=['POST'])
def login():
    """Autentica o usuário e retorna um token JWT"""
    d       = request.json or {}
    usuario = (d.get('usuario') or '').strip().lower()
    senha   = (d.get('senha')   or '').strip()
    ip      = request.remote_addr or 'desconhecido'

    # Validação básica
    if not usuario or not senha:
        return jsonify({'ok': False, 'erro': 'Preencha usuário e senha'}), 400

    # Rate limiting — bloqueia após 5 tentativas em 10 minutos
    if verificar_rate_limit(usuario, ip):
        logger.warning(f"Rate limit atingido para usuario={usuario} ip={ip}")
        return jsonify({
            'ok': False,
            'erro': f'Muitas tentativas. Aguarde {JANELA_MINUTOS} minutos.'
        }), 429

    con = conectar()
    cur = con.cursor(dictionary=True)
    try:
        cur.execute(
            "SELECT id, nome, usuario, senha_hash, perfil FROM usuarios"
            " WHERE usuario = %s AND ativo = TRUE",
            (usuario,)
        )
        user = cur.fetchone()

        if user and verificar_senha(senha, user['senha_hash']):
            # Login bem-sucedido
            cur.execute(
                "UPDATE usuarios SET ultimo_login = %s WHERE id = %s",
                (datetime.utcnow(), user['id'])
            )
            con.commit()
            registrar_tentativa(usuario, ip, True)
            token = gerar_token(user['id'], user['nome'], user['perfil'])
            logger.info(f"Login OK: usuario={usuario} ip={ip}")
            return jsonify({
                'ok':      True,
                'token':   token,
                'nome':    user['nome'],
                'perfil':  user['perfil'],
                'expira':  JWT_EXPIRACAO_HORAS
            })
        else:
            # Login falhou
            registrar_tentativa(usuario, ip, False)
            logger.warning(f"Login FALHOU: usuario={usuario} ip={ip}")
            return jsonify({'ok': False, 'erro': 'Usuário ou senha incorretos'}), 401

    except Exception as e:
        logger.error(f"Erro no login: {e}")
        return jsonify({'ok': False, 'erro': 'Erro interno'}), 500
    finally:
        con.close()


# ─────────────────────────────────────────────────────
# GET /usuarios — listar (somente admin)
# ─────────────────────────────────────────────────────
@app.route('/usuarios', methods=['GET'])
@requer_admin
def listar_usuarios():
    """Lista usuários — somente administradores"""
    con = conectar()
    cur = con.cursor(dictionary=True)
    try:
        cur.execute(
            "SELECT id, nome, usuario, perfil, ativo, ultimo_login, created_at"
            " FROM usuarios ORDER BY id"
        )
        usuarios = cur.fetchall()
        for u in usuarios:
            if u.get('created_at'):   u['created_at']   = str(u['created_at'])
            if u.get('ultimo_login'): u['ultimo_login']  = str(u['ultimo_login'])
        return jsonify(usuarios)
    except Exception as e:
        logger.error(f"Erro ao listar usuarios: {e}")
        return jsonify({'ok': False, 'erro': 'Erro interno'}), 500
    finally:
        con.close()


# ─────────────────────────────────────────────────────
# POST /usuarios — criar novo usuário (somente admin)
# ─────────────────────────────────────────────────────
@app.route('/usuarios', methods=['POST'])
@requer_admin
def criar_usuario():
    """Cria novo usuário com senha em bcrypt"""
    d       = request.json or {}
    nome    = (d.get('nome')    or '').strip()
    usuario = (d.get('usuario') or '').strip().lower()
    senha   = (d.get('senha')   or '').strip()
    perfil  = d.get('perfil', 'usuario')

    if not nome or not usuario or not senha:
        return jsonify({'ok': False, 'erro': 'Preencha todos os campos'}), 400
    if len(senha) < 6:
        return jsonify({'ok': False, 'erro': 'Senha deve ter pelo menos 6 caracteres'}), 400
    if perfil not in ('usuario', 'admin'):
        perfil = 'usuario'

    con = conectar()
    cur = con.cursor()
    try:
        cur.execute(
            "INSERT INTO usuarios (nome, usuario, senha_hash, perfil)"
            " VALUES (%s, %s, %s, %s)",
            (nome, usuario, hash_senha(senha), perfil)
        )
        con.commit()
        logger.info(f"Usuário criado: {usuario}")
        return jsonify({'ok': True, 'id': cur.lastrowid}), 201
    except mysql.connector.IntegrityError:
        return jsonify({'ok': False, 'erro': 'Este usuário já existe'}), 409
    except Exception as e:
        con.rollback()
        logger.error(f"Erro ao criar usuario: {e}")
        return jsonify({'ok': False, 'erro': 'Erro interno'}), 500
    finally:
        con.close()


# ─────────────────────────────────────────────────────
# PUT /usuarios/<id> — atualizar (somente admin)
# ─────────────────────────────────────────────────────
@app.route('/usuarios/<int:id>', methods=['PUT'])
@requer_admin
def atualizar_usuario(id):
    """Atualiza dados de um usuário"""
    d       = request.json or {}
    nome    = (d.get('nome')    or '').strip()
    usuario = (d.get('usuario') or '').strip().lower()
    senha   = (d.get('senha')   or '').strip()
    perfil  = d.get('perfil', 'usuario')

    if not nome or not usuario:
        return jsonify({'ok': False, 'erro': 'Nome e usuário são obrigatórios'}), 400

    con = conectar()
    cur = con.cursor()
    try:
        if senha:
            if len(senha) < 6:
                return jsonify({'ok': False, 'erro': 'Senha deve ter pelo menos 6 caracteres'}), 400
            cur.execute(
                "UPDATE usuarios SET nome=%s, usuario=%s, senha_hash=%s, perfil=%s WHERE id=%s",
                (nome, usuario, hash_senha(senha), perfil, id)
            )
        else:
            cur.execute(
                "UPDATE usuarios SET nome=%s, usuario=%s, perfil=%s WHERE id=%s",
                (nome, usuario, perfil, id)
            )
        con.commit()
        return jsonify({'ok': True})
    except Exception as e:
        con.rollback()
        logger.error(f"Erro ao atualizar usuario {id}: {e}")
        return jsonify({'ok': False, 'erro': 'Erro interno'}), 500
    finally:
        con.close()


# ─────────────────────────────────────────────────────
# PATCH /usuarios/<id>/ativo — ativar/desativar (admin)
# ─────────────────────────────────────────────────────
@app.route('/usuarios/<int:id>/ativo', methods=['PATCH'])
@requer_admin
def toggle_usuario(id):
    """Ativa ou desativa um usuário"""
    d     = request.json or {}
    ativo = bool(d.get('ativo', True))
    con   = conectar()
    cur   = con.cursor()
    try:
        cur.execute("UPDATE usuarios SET ativo=%s WHERE id=%s", (ativo, id))
        con.commit()
        return jsonify({'ok': True})
    except Exception as e:
        con.rollback()
        logger.error(f"Erro ao toggle usuario {id}: {e}")
        return jsonify({'ok': False, 'erro': 'Erro interno'}), 500
    finally:
        con.close()


# ─────────────────────────────────────────────────────
# GET /clientes — listar todos (autenticado)
# ─────────────────────────────────────────────────────
@app.route('/clientes', methods=['GET'])
@requer_autenticacao
def listar_clientes():
    """Retorna todos os clientes com dados relacionados"""
    pagina = max(1, int(request.args.get('pagina', 1)))
    limite = min(100, int(request.args.get('limite', 50)))
    offset = (pagina - 1) * limite

    con = conectar()
    cur = con.cursor(dictionary=True)
    try:
        cur.execute(
            "SELECT * FROM clientes ORDER BY created_at DESC LIMIT %s OFFSET %s",
            (limite, offset)
        )
        clientes = cur.fetchall()

        for c in clientes:
            cid = c['id']

            cur.execute(
                "SELECT * FROM produtos_interesse WHERE cliente_id = %s", (cid,)
            )
            c['produtos'] = cur.fetchall()

            cur.execute(
                "SELECT * FROM encomendas WHERE cliente_id = %s", (cid,)
            )
            c['encomendas'] = cur.fetchall()

            cur.execute(
                "SELECT * FROM compras WHERE cliente_id = %s ORDER BY data DESC", (cid,)
            )
            compras = cur.fetchall()
            for cp in compras:
                if cp.get('data'):       cp['data']       = str(cp['data'])
                if cp.get('created_at'): cp['created_at'] = str(cp['created_at'])
                if cp.get('updated_at'): cp['updated_at'] = str(cp['updated_at'])
                cp['valor_total'] = float(cp.get('valor_total') or 0)
                cp['custo']       = float(cp.get('custo')       or 0)

                cur.execute(
                    "SELECT * FROM pagamentos WHERE compra_id = %s ORDER BY data", (cp['id'],)
                )
                pags = cur.fetchall()
                for pg in pags:
                    if pg.get('data'): pg['data'] = str(pg['data'])
                    pg['valor'] = float(pg.get('valor') or 0)
                cp['pagamentos'] = pags

            c['compras'] = compras
            if c.get('created_at'): c['created_at'] = str(c['created_at'])
            if c.get('updated_at'): c['updated_at'] = str(c['updated_at'])

        return jsonify(clientes)

    except Exception as e:
        logger.error(f"Erro ao listar clientes: {e}")
        return jsonify({'ok': False, 'erro': 'Erro interno'}), 500
    finally:
        con.close()


# ─────────────────────────────────────────────────────
# POST /clientes — criar (autenticado)
# ─────────────────────────────────────────────────────
@app.route('/clientes', methods=['POST'])
@requer_autenticacao
def criar_cliente():
    """Cadastra um novo cliente com todos os dados relacionados"""
    d    = request.json or {}
    nome = (d.get('nome') or '').strip()

    if not nome:
        return jsonify({'ok': False, 'erro': 'Nome é obrigatório'}), 400
    if len(nome) > 150:
        return jsonify({'ok': False, 'erro': 'Nome muito longo (máx 150 caracteres)'}), 400

    con = conectar()
    cur = con.cursor()
    try:
        cur.execute(
            "INSERT INTO clientes (nome, telefone, email, bairro, tag, obs)"
            " VALUES (%s, %s, %s, %s, %s, %s)",
            (
                nome,
                (d.get('telefone') or '')[:20],
                (d.get('email')    or '')[:100],
                (d.get('bairro')   or '')[:100],
                (d.get('tag')      or '')[:50],
                (d.get('obs')      or '')[:2000]
            )
        )
        cliente_id = cur.lastrowid
        _inserir_relacionados(cur, cliente_id, d)
        con.commit()
        logger.info(f"Cliente criado: id={cliente_id} nome={nome}")
        return jsonify({'ok': True, 'id': cliente_id}), 201
    except Exception as e:
        con.rollback()
        logger.error(f"Erro ao criar cliente: {e}")
        return jsonify({'ok': False, 'erro': 'Erro interno'}), 500
    finally:
        con.close()


# ─────────────────────────────────────────────────────
# PUT /clientes/<id> — atualizar (autenticado)
# ─────────────────────────────────────────────────────
@app.route('/clientes/<int:id>', methods=['PUT'])
@requer_autenticacao
def atualizar_cliente(id):
    """Atualiza um cliente existente"""
    d    = request.json or {}
    nome = (d.get('nome') or '').strip()

    if not nome:
        return jsonify({'ok': False, 'erro': 'Nome é obrigatório'}), 400

    con = conectar()
    cur = con.cursor()
    try:
        cur.execute(
            "UPDATE clientes SET nome=%s, telefone=%s, email=%s,"
            " bairro=%s, tag=%s, obs=%s WHERE id=%s",
            (
                nome,
                (d.get('telefone') or '')[:20],
                (d.get('email')    or '')[:100],
                (d.get('bairro')   or '')[:100],
                (d.get('tag')      or '')[:50],
                (d.get('obs')      or '')[:2000],
                id
            )
        )
        cur.execute("DELETE FROM produtos_interesse WHERE cliente_id=%s", (id,))
        cur.execute("DELETE FROM encomendas WHERE cliente_id=%s", (id,))
        cur.execute("DELETE FROM compras WHERE cliente_id=%s", (id,))
        _inserir_relacionados(cur, id, d)
        con.commit()
        return jsonify({'ok': True})
    except Exception as e:
        con.rollback()
        logger.error(f"Erro ao atualizar cliente {id}: {e}")
        return jsonify({'ok': False, 'erro': 'Erro interno'}), 500
    finally:
        con.close()


# ─────────────────────────────────────────────────────
# DELETE /clientes/<id> — excluir (autenticado)
# ─────────────────────────────────────────────────────
@app.route('/clientes/<int:id>', methods=['DELETE'])
@requer_autenticacao
def excluir_cliente(id):
    """Remove um cliente e todos os dados relacionados"""
    con = conectar()
    cur = con.cursor()
    try:
        cur.execute("DELETE FROM clientes WHERE id=%s", (id,))
        con.commit()
        logger.info(f"Cliente removido: id={id}")
        return jsonify({'ok': True})
    except Exception as e:
        con.rollback()
        logger.error(f"Erro ao excluir cliente {id}: {e}")
        return jsonify({'ok': False, 'erro': 'Erro interno'}), 500
    finally:
        con.close()


# ─────────────────────────────────────────────────────
# PATCH /clientes/<cid>/encomenda/<eid> — entregar
# ─────────────────────────────────────────────────────
@app.route('/clientes/<int:cid>/encomenda/<int:eid>', methods=['PATCH'])
@requer_autenticacao
def marcar_entregue(cid, eid):
    """Marca uma encomenda como entregue"""
    con = conectar()
    cur = con.cursor()
    try:
        cur.execute(
            "UPDATE encomendas SET status='Entregue'"
            " WHERE id=%s AND cliente_id=%s",
            (eid, cid)
        )
        con.commit()
        return jsonify({'ok': True})
    except Exception as e:
        con.rollback()
        logger.error(f"Erro ao marcar encomenda {eid}: {e}")
        return jsonify({'ok': False, 'erro': 'Erro interno'}), 500
    finally:
        con.close()


# ─────────────────────────────────────────────────────
# GET /dashboard — KPIs (autenticado)
# ─────────────────────────────────────────────────────
@app.route('/dashboard', methods=['GET'])
@requer_autenticacao
def dashboard():
    """Retorna todos os dados do dashboard para o mês selecionado"""
    mes = (request.args.get('mes') or '').strip()
    con = conectar()
    cur = con.cursor(dictionary=True)
    try:
        cur.execute("SELECT COUNT(*) AS total FROM clientes")
        total_clientes = cur.fetchone()['total']

        cur.execute(
            "SELECT COALESCE(SUM(valor_total),0) AS total FROM compras"
            " WHERE DATE_FORMAT(data,'%Y-%m')=%s", (mes,)
        )
        vendas_mes = float(cur.fetchone()['total'])

        cur.execute(
            "SELECT COALESCE(SUM(valor),0) AS total FROM pagamentos"
            " WHERE DATE_FORMAT(data,'%Y-%m')=%s", (mes,)
        )
        recebido_mes = float(cur.fetchone()['total'])

        cur.execute("""
            SELECT COALESCE(SUM(cp.valor_total),0)
                 - COALESCE(SUM(pg.total_pago),0) AS a_receber
            FROM compras cp
            LEFT JOIN (
                SELECT compra_id, SUM(valor) AS total_pago
                FROM pagamentos GROUP BY compra_id
            ) pg ON pg.compra_id = cp.id
        """)
        a_receber = float(max(0, cur.fetchone()['a_receber'] or 0))

        cur.execute(
            "SELECT COALESCE(SUM(valor_total-custo),0) AS lucro FROM compras"
        )
        lucro = float(cur.fetchone()['lucro'] or 0)

        cur.execute(
            "SELECT COUNT(*) AS total FROM encomendas WHERE status='Pendente'"
        )
        enc_pendentes = cur.fetchone()['total']

        cur.execute("""
            SELECT cl.id, cl.nome,
                   SUM(cp.valor_total) AS total_compras,
                   COUNT(cp.id)        AS qtd_compras
            FROM compras cp JOIN clientes cl ON cl.id=cp.cliente_id
            WHERE DATE_FORMAT(cp.data,'%%Y-%%m')=%s
            GROUP BY cl.id, cl.nome
            ORDER BY total_compras DESC LIMIT 6
        """, (mes,))
        top_mes = cur.fetchall()
        for t in top_mes: t['total_compras'] = float(t['total_compras'])

        cur.execute("""
            SELECT cp.id, cp.descricao, cp.data, cp.valor_total,
                   cl.id AS cliente_id, cl.nome
            FROM compras cp JOIN clientes cl ON cl.id=cp.cliente_id
            WHERE DATE_FORMAT(cp.data,'%%Y-%%m')=%s
            ORDER BY cp.data DESC LIMIT 6
        """, (mes,))
        ultimas = cur.fetchall()
        for u in ultimas:
            if u.get('data'): u['data'] = str(u['data'])
            u['valor_total'] = float(u['valor_total'])

        cur.execute("""
            SELECT cl.id, cl.nome,
                   SUM(cp.valor_total)              AS total_compras,
                   COALESCE(SUM(pg.total_pago),0)   AS total_pago,
                   SUM(cp.valor_total)
                   - COALESCE(SUM(pg.total_pago),0) AS divida
            FROM compras cp JOIN clientes cl ON cl.id=cp.cliente_id
            LEFT JOIN (
                SELECT compra_id, SUM(valor) AS total_pago
                FROM pagamentos GROUP BY compra_id
            ) pg ON pg.compra_id=cp.id
            GROUP BY cl.id, cl.nome
            HAVING divida > 0
            ORDER BY divida DESC LIMIT 6
        """)
        devedores = cur.fetchall()
        for d in devedores:
            d['total_compras'] = float(d['total_compras'])
            d['total_pago']    = float(d['total_pago'])
            d['divida']        = float(d['divida'])

        cur.execute("""
            SELECT cl.id, cl.nome,
                   MAX(pg.data)                       AS ultimo_pagamento,
                   SUM(cp.valor_total)
                   - COALESCE(SUM(pg2.total_pago),0)  AS divida
            FROM compras cp JOIN clientes cl ON cl.id=cp.cliente_id
            LEFT JOIN pagamentos pg ON pg.compra_id=cp.id
            LEFT JOIN (
                SELECT compra_id, SUM(valor) AS total_pago
                FROM pagamentos GROUP BY compra_id
            ) pg2 ON pg2.compra_id=cp.id
            GROUP BY cl.id, cl.nome
            HAVING divida > 0
            ORDER BY ultimo_pagamento ASC LIMIT 6
        """)
        sem_pagar = cur.fetchall()
        for s in sem_pagar:
            if s.get('ultimo_pagamento'):
                s['ultimo_pagamento'] = str(s['ultimo_pagamento'])
            s['divida'] = float(s['divida'] or 0)

        cur.execute("""
            SELECT cl.id, cl.nome, MAX(cp.data) AS ultima_compra
            FROM clientes cl
            LEFT JOIN compras cp ON cp.cliente_id=cl.id
            GROUP BY cl.id, cl.nome
            HAVING ultima_compra IS NOT NULL
            ORDER BY ultima_compra ASC LIMIT 6
        """)
        sem_comprar = cur.fetchall()
        for s in sem_comprar:
            if s.get('ultima_compra'):
                s['ultima_compra'] = str(s['ultima_compra'])

        cur.execute("""
            SELECT e.id, e.produto, e.quantidade, e.status,
                   cl.id AS cliente_id, cl.nome, cl.telefone
            FROM encomendas e JOIN clientes cl ON cl.id=e.cliente_id
            WHERE e.status='Pendente'
            ORDER BY e.id DESC LIMIT 10
        """)
        enc_lista = cur.fetchall()

        cur.execute("""
            SELECT DATE_FORMAT(data,'%Y-%m') AS mes,
                   SUM(valor_total)           AS vendas,
                   COUNT(DISTINCT cliente_id) AS clientes
            FROM compras WHERE data IS NOT NULL
            GROUP BY mes ORDER BY mes DESC LIMIT 24
        """)
        hist_vendas = cur.fetchall()

        cur.execute("""
            SELECT DATE_FORMAT(data,'%Y-%m') AS mes, SUM(valor) AS recebido
            FROM pagamentos WHERE data IS NOT NULL GROUP BY mes
        """)
        hist_pag = {r['mes']: float(r['recebido']) for r in cur.fetchall()}

        historico = []
        for h in hist_vendas:
            m = h['mes']
            historico.append({
                'mes':      m,
                'vendas':   float(h['vendas']),
                'recebido': hist_pag.get(m, 0),
                'clientes': h['clientes']
            })

        return jsonify({
            'total_clientes':  total_clientes,
            'vendas_mes':      vendas_mes,
            'recebido_mes':    recebido_mes,
            'a_receber':       a_receber,
            'lucro':           lucro,
            'enc_pendentes':   enc_pendentes,
            'top_mes':         top_mes,
            'ultimas_vendas':  ultimas,
            'devedores':       devedores,
            'sem_pagar':       sem_pagar,
            'sem_comprar':     sem_comprar,
            'enc_lista':       enc_lista,
            'historico':       historico
        })

    except Exception as e:
        logger.error(f"Erro no dashboard: {e}")
        return jsonify({'ok': False, 'erro': 'Erro interno'}), 500
    finally:
        con.close()


# ─────────────────────────────────────────────────────
# GET /repasses — por fornecedor (autenticado)
# ─────────────────────────────────────────────────────
@app.route('/repasses', methods=['GET'])
@requer_autenticacao
def repasses():
    """Retorna dados de repasse agrupados por fornecedor"""
    con = conectar()
    cur = con.cursor(dictionary=True)
    try:
        cur.execute("""
            SELECT fornecedor,
                   COUNT(id)                                     AS qtd_vendas,
                   SUM(valor_total)                              AS vendas,
                   SUM(custo)                                    AS custo,
                   SUM(valor_total - custo)                      AS lucro,
                   SUM(CASE WHEN repassado=0 THEN custo ELSE 0 END) AS pendente,
                   SUM(CASE WHEN repassado=1 THEN custo ELSE 0 END) AS repassado_total
            FROM compras
            WHERE fornecedor IS NOT NULL AND fornecedor != ''
            GROUP BY fornecedor ORDER BY vendas DESC
        """)
        por_fornecedor = cur.fetchall()
        for f in por_fornecedor:
            f['vendas']          = float(f['vendas']          or 0)
            f['custo']           = float(f['custo']           or 0)
            f['lucro']           = float(f['lucro']           or 0)
            f['pendente']        = float(f['pendente']        or 0)
            f['repassado_total'] = float(f['repassado_total'] or 0)

        cur.execute("""
            SELECT cp.id, cp.descricao, cp.data, cp.valor_total,
                   cp.custo, cp.fornecedor, cp.repassado,
                   cl.id AS cliente_id, cl.nome
            FROM compras cp JOIN clientes cl ON cl.id=cp.cliente_id
            WHERE cp.fornecedor IS NOT NULL AND cp.fornecedor != ''
            ORDER BY cp.data DESC
        """)
        lista = cur.fetchall()
        for r in lista:
            if r.get('data'): r['data'] = str(r['data'])
            r['valor_total'] = float(r['valor_total'] or 0)
            r['custo']       = float(r['custo']       or 0)

        return jsonify({'por_fornecedor': por_fornecedor, 'lista': lista})

    except Exception as e:
        logger.error(f"Erro em repasses: {e}")
        return jsonify({'ok': False, 'erro': 'Erro interno'}), 500
    finally:
        con.close()


# ─────────────────────────────────────────────────────
# GET /encomendas — com filtro (autenticado)
# ─────────────────────────────────────────────────────
@app.route('/encomendas', methods=['GET'])
@requer_autenticacao
def encomendas():
    """Retorna encomendas filtradas por status"""
    status = request.args.get('status', 'Pendente')
    if status not in ('Pendente', 'Entregue'):
        status = 'Pendente'

    con = conectar()
    cur = con.cursor(dictionary=True)
    try:
        cur.execute("""
            SELECT e.id, e.produto, e.quantidade, e.status,
                   cl.id AS cliente_id, cl.nome, cl.telefone
            FROM encomendas e JOIN clientes cl ON cl.id=e.cliente_id
            WHERE e.status=%s ORDER BY e.id DESC
        """, (status,))
        return jsonify(cur.fetchall())
    except Exception as e:
        logger.error(f"Erro em encomendas: {e}")
        return jsonify({'ok': False, 'erro': 'Erro interno'}), 500
    finally:
        con.close()


# ─────────────────────────────────────────────────────
# GET /fornecedores — lista (autenticado)
# ─────────────────────────────────────────────────────
@app.route('/fornecedores', methods=['GET'])
@requer_autenticacao
def listar_fornecedores():
    """Retorna lista de fornecedores cadastrados"""
    con = conectar()
    cur = con.cursor(dictionary=True)
    try:
        cur.execute("SELECT * FROM fornecedores ORDER BY nome")
        return jsonify(cur.fetchall())
    except Exception as e:
        logger.error(f"Erro em fornecedores: {e}")
        return jsonify({'ok': False, 'erro': 'Erro interno'}), 500
    finally:
        con.close()


# ─────────────────────────────────────────────────────
# INICIAR O SERVIDOR
# ─────────────────────────────────────────────────────
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
