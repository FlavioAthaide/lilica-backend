"""
=======================================================
LILICA VENDAS — Backend Flask + MySQL (Railway)
Login gerenciado pelo banco de dados
=======================================================
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import mysql.connector
import hashlib
import os

app = Flask(__name__, static_folder='static')
CORS(app)

# =====================================================
# CONFIGURAÇÃO DO BANCO — credenciais do Railway
# =====================================================
DB_CONFIG = {
    "host":     os.environ.get("MYSQLHOST",     "mysql.railway.internal"),
    "port":     int(os.environ.get("MYSQLPORT",  3306)),
    "user":     os.environ.get("MYSQLUSER",     "root"),
    "password": os.environ.get("MYSQLPASSWORD", "DVwqBOGXCkDPuWFvLKuZtymmfxilWcIX"),
    "database": os.environ.get("MYSQLDATABASE", "railway")
}

def conectar():
    return mysql.connector.connect(**DB_CONFIG)

# =====================================================
# SEGURANÇA — hash de senha
# =====================================================
SALT = 'lilica2025'

def hash_senha(senha):
    """Gera hash SHA-256 da senha com salt"""
    return hashlib.sha256((senha + SALT).encode()).hexdigest()


# ─────────────────────────────────────────────────────
# SERVIR O FRONTEND
# ─────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')


# ─────────────────────────────────────────────────────
# POST /login — verificar usuário e senha no banco
# ─────────────────────────────────────────────────────

@app.route('/login', methods=['POST'])
def login():
    """Verifica credenciais no banco de dados"""
    d = request.json
    usuario  = d.get('usuario', '').strip().lower()
    senha    = d.get('senha', '').strip()

    if not usuario or not senha:
        return jsonify({'ok': False, 'erro': 'Preencha usuário e senha'}), 400

    con = conectar()
    cur = con.cursor(dictionary=True)
    try:
        cur.execute(
            "SELECT id, nome, usuario FROM usuarios"
            " WHERE usuario = %s AND senha_hash = %s AND ativo = TRUE",
            (usuario, hash_senha(senha))
        )
        user = cur.fetchone()
        if user:
            return jsonify({
                'ok':      True,
                'id':      user['id'],
                'nome':    user['nome'],
                'usuario': user['usuario']
            })
        else:
            return jsonify({'ok': False, 'erro': 'Usuário ou senha incorretos'}), 401
    finally:
        con.close()


# ─────────────────────────────────────────────────────
# GET /usuarios — listar usuários (sem mostrar senhas)
# ─────────────────────────────────────────────────────

@app.route('/usuarios', methods=['GET'])
def listar_usuarios():
    """Lista todos os usuários sem expor as senhas"""
    con = conectar()
    cur = con.cursor(dictionary=True)
    cur.execute(
        "SELECT id, nome, usuario, ativo, created_at FROM usuarios ORDER BY id"
    )
    usuarios = cur.fetchall()
    for u in usuarios:
        if u.get('created_at'): u['created_at'] = str(u['created_at'])
    con.close()
    return jsonify(usuarios)


# ─────────────────────────────────────────────────────
# POST /usuarios — criar novo usuário
# ─────────────────────────────────────────────────────

@app.route('/usuarios', methods=['POST'])
def criar_usuario():
    """Cria um novo usuário com senha em hash"""
    d = request.json
    nome    = d.get('nome', '').strip()
    usuario = d.get('usuario', '').strip().lower()
    senha   = d.get('senha', '').strip()

    if not nome or not usuario or not senha:
        return jsonify({'ok': False, 'erro': 'Preencha todos os campos'}), 400

    con = conectar()
    cur = con.cursor()
    try:
        cur.execute(
            "INSERT INTO usuarios (nome, usuario, senha_hash) VALUES (%s, %s, %s)",
            (nome, usuario, hash_senha(senha))
        )
        con.commit()
        return jsonify({'ok': True, 'id': cur.lastrowid}), 201
    except mysql.connector.IntegrityError:
        return jsonify({'ok': False, 'erro': 'Este usuário já existe'}), 409
    except Exception as e:
        con.rollback()
        return jsonify({'ok': False, 'erro': str(e)}), 500
    finally:
        con.close()


# ─────────────────────────────────────────────────────
# PUT /usuarios/<id> — atualizar usuário ou senha
# ─────────────────────────────────────────────────────

@app.route('/usuarios/<int:id>', methods=['PUT'])
def atualizar_usuario(id):
    """Atualiza nome, usuário e/ou senha"""
    d = request.json
    con = conectar()
    cur = con.cursor()
    try:
        # Se vier nova senha, atualiza o hash
        if d.get('senha'):
            cur.execute(
                "UPDATE usuarios SET nome=%s, usuario=%s, senha_hash=%s WHERE id=%s",
                (d.get('nome'), d.get('usuario','').lower(), hash_senha(d.get('senha')), id)
            )
        else:
            # Sem nova senha, mantém a atual
            cur.execute(
                "UPDATE usuarios SET nome=%s, usuario=%s WHERE id=%s",
                (d.get('nome'), d.get('usuario','').lower(), id)
            )
        con.commit()
        return jsonify({'ok': True})
    except Exception as e:
        con.rollback()
        return jsonify({'ok': False, 'erro': str(e)}), 500
    finally:
        con.close()


# ─────────────────────────────────────────────────────
# PATCH /usuarios/<id>/ativo — ativar ou desativar
# ─────────────────────────────────────────────────────

@app.route('/usuarios/<int:id>/ativo', methods=['PATCH'])
def toggle_usuario(id):
    """Ativa ou desativa um usuário sem deletar"""
    d = request.json
    ativo = bool(d.get('ativo', True))
    con = conectar()
    cur = con.cursor()
    try:
        cur.execute("UPDATE usuarios SET ativo=%s WHERE id=%s", (ativo, id))
        con.commit()
        return jsonify({'ok': True})
    except Exception as e:
        con.rollback()
        return jsonify({'ok': False, 'erro': str(e)}), 500
    finally:
        con.close()


# ─────────────────────────────────────────────────────
# GET /clientes
# ─────────────────────────────────────────────────────

@app.route('/clientes', methods=['GET'])
def listar_clientes():
    con = conectar()
    cur = con.cursor(dictionary=True)
    cur.execute("SELECT * FROM clientes ORDER BY created_at DESC")
    clientes = cur.fetchall()
    for c in clientes:
        cid = c['id']
        cur.execute("SELECT * FROM produtos_interesse WHERE cliente_id = %s", (cid,))
        c['produtos'] = cur.fetchall()
        cur.execute("SELECT * FROM encomendas WHERE cliente_id = %s", (cid,))
        c['encomendas'] = cur.fetchall()
        cur.execute("SELECT * FROM compras WHERE cliente_id = %s ORDER BY data DESC", (cid,))
        compras = cur.fetchall()
        for cp in compras:
            if cp.get('data'):       cp['data']       = str(cp['data'])
            if cp.get('created_at'): cp['created_at'] = str(cp['created_at'])
            cp['valor_total'] = float(cp.get('valor_total') or 0)
            cp['custo']       = float(cp.get('custo')       or 0)
            cur.execute("SELECT * FROM pagamentos WHERE compra_id = %s ORDER BY data", (cp['id'],))
            pags = cur.fetchall()
            for pg in pags:
                if pg.get('data'): pg['data'] = str(pg['data'])
                pg['valor'] = float(pg.get('valor') or 0)
            cp['pagamentos'] = pags
        c['compras'] = compras
        if c.get('created_at'): c['created_at'] = str(c['created_at'])
    con.close()
    return jsonify(clientes)


@app.route('/clientes', methods=['POST'])
def criar_cliente():
    d = request.json
    con = conectar()
    cur = con.cursor()
    try:
        cur.execute(
            "INSERT INTO clientes (nome, telefone, email, bairro, tag, obs)"
            " VALUES (%s, %s, %s, %s, %s, %s)",
            (d.get('nome'), d.get('telefone'), d.get('email'),
             d.get('bairro'), d.get('tag'), d.get('obs'))
        )
        cliente_id = cur.lastrowid
        for p in d.get('produtos', []):
            if p.get('nome'):
                cur.execute(
                    "INSERT INTO produtos_interesse (cliente_id, nome, quantidade)"
                    " VALUES (%s, %s, %s)",
                    (cliente_id, p.get('nome'), p.get('qtd', ''))
                )
        for e in d.get('encomendas', []):
            if e.get('produto'):
                cur.execute(
                    "INSERT INTO encomendas (cliente_id, produto, quantidade, status)"
                    " VALUES (%s, %s, %s, %s)",
                    (cliente_id, e.get('produto'), e.get('qtd', ''), e.get('status', 'Pendente'))
                )
        for c in d.get('compras', []):
            cur.execute(
                "INSERT INTO compras"
                " (cliente_id, descricao, data, valor_total, fornecedor, custo, repassado)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (cliente_id, c.get('desc', ''), c.get('data') or None,
                 float(c.get('total', 0)), c.get('fornecedor', ''),
                 float(c.get('custo', 0)), bool(c.get('repassado', False)))
            )
            compra_id = cur.lastrowid
            for pg in c.get('pagamentos', []):
                cur.execute(
                    "INSERT INTO pagamentos (compra_id, data, valor, forma, banco)"
                    " VALUES (%s, %s, %s, %s, %s)",
                    (compra_id, pg.get('data') or None,
                     float(pg.get('valor', 0)), pg.get('forma', ''), pg.get('banco', ''))
                )
        con.commit()
        return jsonify({'ok': True, 'id': cliente_id}), 201
    except Exception as e:
        con.rollback()
        return jsonify({'ok': False, 'erro': str(e)}), 500
    finally:
        con.close()


@app.route('/clientes/<int:id>', methods=['PUT'])
def atualizar_cliente(id):
    d = request.json
    con = conectar()
    cur = con.cursor()
    try:
        cur.execute(
            "UPDATE clientes SET nome=%s, telefone=%s, email=%s,"
            " bairro=%s, tag=%s, obs=%s WHERE id=%s",
            (d.get('nome'), d.get('telefone'), d.get('email'),
             d.get('bairro'), d.get('tag'), d.get('obs'), id)
        )
        cur.execute("DELETE FROM produtos_interesse WHERE cliente_id=%s", (id,))
        cur.execute("DELETE FROM encomendas WHERE cliente_id=%s", (id,))
        cur.execute("DELETE FROM compras WHERE cliente_id=%s", (id,))
        for p in d.get('produtos', []):
            if p.get('nome'):
                cur.execute(
                    "INSERT INTO produtos_interesse (cliente_id, nome, quantidade)"
                    " VALUES (%s, %s, %s)",
                    (id, p.get('nome'), p.get('qtd', ''))
                )
        for e in d.get('encomendas', []):
            if e.get('produto'):
                cur.execute(
                    "INSERT INTO encomendas (cliente_id, produto, quantidade, status)"
                    " VALUES (%s, %s, %s, %s)",
                    (id, e.get('produto'), e.get('qtd', ''), e.get('status', 'Pendente'))
                )
        for c in d.get('compras', []):
            cur.execute(
                "INSERT INTO compras (cliente_id, descricao, data,"
                " valor_total, fornecedor, custo, repassado)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (id, c.get('desc', ''), c.get('data') or None,
                 float(c.get('total', 0)), c.get('fornecedor', ''),
                 float(c.get('custo', 0)), bool(c.get('repassado', False)))
            )
            compra_id = cur.lastrowid
            for pg in c.get('pagamentos', []):
                cur.execute(
                    "INSERT INTO pagamentos (compra_id, data, valor, forma, banco)"
                    " VALUES (%s, %s, %s, %s, %s)",
                    (compra_id, pg.get('data') or None,
                     float(pg.get('valor', 0)), pg.get('forma', ''), pg.get('banco', ''))
                )
        con.commit()
        return jsonify({'ok': True})
    except Exception as e:
        con.rollback()
        return jsonify({'ok': False, 'erro': str(e)}), 500
    finally:
        con.close()


@app.route('/clientes/<int:id>', methods=['DELETE'])
def excluir_cliente(id):
    con = conectar()
    cur = con.cursor()
    try:
        cur.execute("DELETE FROM clientes WHERE id=%s", (id,))
        con.commit()
        return jsonify({'ok': True})
    except Exception as e:
        con.rollback()
        return jsonify({'ok': False, 'erro': str(e)}), 500
    finally:
        con.close()


@app.route('/clientes/<int:cid>/encomenda/<int:eid>', methods=['PATCH'])
def marcar_entregue(cid, eid):
    con = conectar()
    cur = con.cursor()
    try:
        cur.execute(
            "UPDATE encomendas SET status='Entregue' WHERE id=%s AND cliente_id=%s",
            (eid, cid)
        )
        con.commit()
        return jsonify({'ok': True})
    except Exception as e:
        con.rollback()
        return jsonify({'ok': False, 'erro': str(e)}), 500
    finally:
        con.close()


@app.route('/dashboard', methods=['GET'])
def dashboard():
    mes = request.args.get('mes', '')
    con = conectar()
    cur = con.cursor(dictionary=True)
    cur.execute("SELECT COUNT(*) AS total FROM clientes")
    total_clientes = cur.fetchone()['total']
    cur.execute("SELECT COALESCE(SUM(valor_total),0) AS total FROM compras WHERE DATE_FORMAT(data,'%Y-%m')=%s",(mes,))
    vendas_mes = float(cur.fetchone()['total'])
    cur.execute("SELECT COALESCE(SUM(valor),0) AS total FROM pagamentos WHERE DATE_FORMAT(data,'%Y-%m')=%s",(mes,))
    recebido_mes = float(cur.fetchone()['total'])
    cur.execute("""
        SELECT COALESCE(SUM(cp.valor_total),0)-COALESCE(SUM(pg.total_pago),0) AS a_receber
        FROM compras cp
        LEFT JOIN (SELECT compra_id,SUM(valor) AS total_pago FROM pagamentos GROUP BY compra_id) pg
        ON pg.compra_id=cp.id
    """)
    a_receber = float(max(0, cur.fetchone()['a_receber'] or 0))
    cur.execute("SELECT COALESCE(SUM(valor_total-custo),0) AS lucro FROM compras")
    lucro = float(cur.fetchone()['lucro'] or 0)
    cur.execute("SELECT COUNT(*) AS total FROM encomendas WHERE status='Pendente'")
    enc_pendentes = cur.fetchone()['total']
    cur.execute("""
        SELECT cl.id,cl.nome,SUM(cp.valor_total) AS total_compras,COUNT(cp.id) AS qtd_compras
        FROM compras cp JOIN clientes cl ON cl.id=cp.cliente_id
        WHERE DATE_FORMAT(cp.data,'%%Y-%%m')=%s
        GROUP BY cl.id,cl.nome ORDER BY total_compras DESC LIMIT 6
    """,(mes,))
    top_mes = cur.fetchall()
    for t in top_mes: t['total_compras']=float(t['total_compras'])
    cur.execute("""
        SELECT cp.id,cp.descricao,cp.data,cp.valor_total,cl.id AS cliente_id,cl.nome
        FROM compras cp JOIN clientes cl ON cl.id=cp.cliente_id
        WHERE DATE_FORMAT(cp.data,'%%Y-%%m')=%s ORDER BY cp.data DESC LIMIT 6
    """,(mes,))
    ultimas=cur.fetchall()
    for u in ultimas:
        if u.get('data'): u['data']=str(u['data'])
        u['valor_total']=float(u['valor_total'])
    cur.execute("""
        SELECT cl.id,cl.nome,SUM(cp.valor_total) AS total_compras,
               COALESCE(SUM(pg.total_pago),0) AS total_pago,
               SUM(cp.valor_total)-COALESCE(SUM(pg.total_pago),0) AS divida
        FROM compras cp JOIN clientes cl ON cl.id=cp.cliente_id
        LEFT JOIN (SELECT compra_id,SUM(valor) AS total_pago FROM pagamentos GROUP BY compra_id) pg
        ON pg.compra_id=cp.id
        GROUP BY cl.id,cl.nome HAVING divida>0 ORDER BY divida DESC LIMIT 6
    """)
    devedores=cur.fetchall()
    for d in devedores:
        d['total_compras']=float(d['total_compras'])
        d['total_pago']=float(d['total_pago'])
        d['divida']=float(d['divida'])
    cur.execute("""
        SELECT cl.id,cl.nome,MAX(pg.data) AS ultimo_pagamento,
               SUM(cp.valor_total)-COALESCE(SUM(pg2.total_pago),0) AS divida
        FROM compras cp JOIN clientes cl ON cl.id=cp.cliente_id
        LEFT JOIN pagamentos pg ON pg.compra_id=cp.id
        LEFT JOIN (SELECT compra_id,SUM(valor) AS total_pago FROM pagamentos GROUP BY compra_id) pg2
        ON pg2.compra_id=cp.id
        GROUP BY cl.id,cl.nome HAVING divida>0 ORDER BY ultimo_pagamento ASC LIMIT 6
    """)
    sem_pagar=cur.fetchall()
    for s in sem_pagar:
        if s.get('ultimo_pagamento'): s['ultimo_pagamento']=str(s['ultimo_pagamento'])
        s['divida']=float(s['divida'] or 0)
    cur.execute("""
        SELECT cl.id,cl.nome,MAX(cp.data) AS ultima_compra
        FROM clientes cl LEFT JOIN compras cp ON cp.cliente_id=cl.id
        GROUP BY cl.id,cl.nome HAVING ultima_compra IS NOT NULL
        ORDER BY ultima_compra ASC LIMIT 6
    """)
    sem_comprar=cur.fetchall()
    for s in sem_comprar:
        if s.get('ultima_compra'): s['ultima_compra']=str(s['ultima_compra'])
    cur.execute("""
        SELECT e.id,e.produto,e.quantidade,e.status,cl.id AS cliente_id,cl.nome,cl.telefone
        FROM encomendas e JOIN clientes cl ON cl.id=e.cliente_id
        WHERE e.status='Pendente' ORDER BY e.id DESC LIMIT 10
    """)
    enc_lista=cur.fetchall()
    cur.execute("""
        SELECT DATE_FORMAT(data,'%Y-%m') AS mes,SUM(valor_total) AS vendas,
               COUNT(DISTINCT cliente_id) AS clientes
        FROM compras WHERE data IS NOT NULL GROUP BY mes ORDER BY mes DESC LIMIT 24
    """)
    hist_vendas=cur.fetchall()
    cur.execute("SELECT DATE_FORMAT(data,'%Y-%m') AS mes,SUM(valor) AS recebido FROM pagamentos WHERE data IS NOT NULL GROUP BY mes")
    hist_pag={r['mes']:float(r['recebido']) for r in cur.fetchall()}
    historico=[]
    for h in hist_vendas:
        m=h['mes']
        historico.append({'mes':m,'vendas':float(h['vendas']),'recebido':hist_pag.get(m,0),'clientes':h['clientes']})
    con.close()
    return jsonify({'total_clientes':total_clientes,'vendas_mes':vendas_mes,'recebido_mes':recebido_mes,
        'a_receber':a_receber,'lucro':lucro,'enc_pendentes':enc_pendentes,'top_mes':top_mes,
        'ultimas_vendas':ultimas,'devedores':devedores,'sem_pagar':sem_pagar,
        'sem_comprar':sem_comprar,'enc_lista':enc_lista,'historico':historico})


@app.route('/repasses', methods=['GET'])
def repasses():
    con = conectar()
    cur = con.cursor(dictionary=True)
    cur.execute("""
        SELECT fornecedor,COUNT(id) AS qtd_vendas,SUM(valor_total) AS vendas,
               SUM(custo) AS custo,SUM(valor_total-custo) AS lucro,
               SUM(CASE WHEN repassado=0 THEN custo ELSE 0 END) AS pendente,
               SUM(CASE WHEN repassado=1 THEN custo ELSE 0 END) AS repassado_total
        FROM compras WHERE fornecedor IS NOT NULL AND fornecedor!=''
        GROUP BY fornecedor ORDER BY vendas DESC
    """)
    por_fornecedor=cur.fetchall()
    for f in por_fornecedor:
        f['vendas']=float(f['vendas'] or 0)
        f['custo']=float(f['custo'] or 0)
        f['lucro']=float(f['lucro'] or 0)
        f['pendente']=float(f['pendente'] or 0)
        f['repassado_total']=float(f['repassado_total'] or 0)
    cur.execute("""
        SELECT cp.id,cp.descricao,cp.data,cp.valor_total,cp.custo,cp.fornecedor,cp.repassado,
               cl.id AS cliente_id,cl.nome
        FROM compras cp JOIN clientes cl ON cl.id=cp.cliente_id
        WHERE cp.fornecedor IS NOT NULL AND cp.fornecedor!='' ORDER BY cp.data DESC
    """)
    lista=cur.fetchall()
    for r in lista:
        if r.get('data'): r['data']=str(r['data'])
        r['valor_total']=float(r['valor_total'] or 0)
        r['custo']=float(r['custo'] or 0)
    con.close()
    return jsonify({'por_fornecedor':por_fornecedor,'lista':lista})


@app.route('/encomendas', methods=['GET'])
def encomendas():
    status=request.args.get('status','Pendente')
    con=conectar()
    cur=con.cursor(dictionary=True)
    cur.execute("""
        SELECT e.id,e.produto,e.quantidade,e.status,cl.id AS cliente_id,cl.nome,cl.telefone
        FROM encomendas e JOIN clientes cl ON cl.id=e.cliente_id
        WHERE e.status=%s ORDER BY e.id DESC
    """,(status,))
    resultado=cur.fetchall()
    con.close()
    return jsonify(resultado)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
