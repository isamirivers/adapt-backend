try:
    from flask import Flask, render_template, send_file, request, Response, abort, send_from_directory, redirect
    from pymongo import MongoClient
    import pymongo.errors
    import json
    import random
    import bcrypt
    from flask_cors import CORS
    import re
    from uuid import uuid4
    import datetime
    import time
    import asyncio
    import gevent
    import string
except:
    print('pip install -r requirements.txt')

app = Flask(__name__,
            static_url_path='',
            static_folder='adapt-web',)
CORS(app)

client = MongoClient("mongodb://127.0.0.1:27017",
                     serverSelectionTimeoutMS=1)

connected_clients = []

try:
    client.server_info()
    db = client['adapt']
except pymongo.errors.ServerSelectionTimeoutError as err:
    print('Фатальная ошибка: Не могу подключиться к базе данных.')
    exit()

def generate_chat_code(length):
    chars = string.ascii_uppercase + string.ascii_lowercase + string.digits
    codee = ''.join(random.choice(chars) for _ in range(length))
    return codee

def is_valid_password(password):
    # Пароль должен быть длиной больше 4 символов
    return len(password) > 4 and len(password) <= 3000

def is_valid_login(login):
    # Логин должен быть длиной не менее 4 символов и содержать только буквы и цифры
    pattern = r"^[a-zA-Z0-9]{4,}$"
    return bool(re.match(pattern, login)) and len(login) <= 30

def is_valid_name(name):
    # Имя должно быть длиной не менее 1 и не более 30 символов.
    return len(name) > 0 and len(name) <= 30

def is_valid_message(name):
    # Сообщение должно быть длиной не менее 1 и не более 3000 символов.
    return len(name) > 0 and len(name) <= 3000

@app.route('/')
def index():
    return render_template('index.html', text="Adapt")

@app.route('/web')
def adapt_web():
    return send_file('adapt-web/index.html', mimetype='text/html')
    #return render_template('index.html', text="Скоро")

@app.route('/res/<image>')
def get_image(image):
    return send_file('templates/'+image, mimetype='image/jpeg')

@app.before_request
def before_request():
    for token in db.tokens.find():
        if int(token['expires']) < datetime.datetime.now().timestamp():
            db.tokens.delete_one({
                'token': token['token']
            })

@app.errorhandler(Exception)
def http_error_handler(error):
    if error.code:
        # if not request.headers.get('accept') in ['*/*', 'application/json']:
        #     return render_template('index.html', text=error.code), error.code
        # else:
        resp = Response(response='{"http_error": ['+str(error.code) + ', "' + error.name + '"], "response": "' + error.description + '"}',
                        status=error.code,
                        mimetype="application/json")
        return resp

@app.route('/api/register_user', methods=['POST'])
def register_user():
    """
    РЕГИСТРАЦИЯ ПОЛЬЗОВАТЕЛЯ

    Принимает:
    name, login, password

    Возвращает:
    response: true/false
    """
    j = request.get_json(force=True)

    try:
        j['name']
        j['login']
        j['password']
    except:
        abort(400, 'Эндпоинт принимает: name, login, password')

    try:
        db['users'].find({'login': j['login']})[0]
    except IndexError:
        pass
    else:
        return json.dumps({"response": "Пользователь с таким логином уже существует"}, ensure_ascii=False), 400
    
    password = j['password']
    if not is_valid_password(password):
        return json.dumps({"response": "Пароль должен содержать минимум 5 символов"}, ensure_ascii=False), 400

    login = j['login']
    if not is_valid_login(login):
        return json.dumps({"response": "Логин должен иметь только буквы и цифры, не менее 4 символов и не более 30"}, ensure_ascii=False), 400

    name = j['name']
    if not is_valid_name(name):
        return json.dumps({"response": "Имя должно быть не более 30 символов, и не менее 1"}, ensure_ascii=False), 400
    
    try:
        id = db.users.find().limit(1).sort('id', -1)[0]['id']+1
    except IndexError:
        id = 0

    password = password.encode()
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password, salt)

    db['users'].insert_one(
        {
            "id": id,
            "login": login,
            "name": name,
            "avatar": f"https://blazer321.ru/res/ava%20({random.randint(1,16)}).png",
            "online": False,
            "password": hashed
        }
    )
    return json.dumps(
        {"response": True}
    ), 200

@app.route('/api/user_registered/<login>')
def user_registered(login):
    """
    ПРОВЕРКА, ЗАРЕГИСТРИРОВАН ЛИ ПОЛЬЗОВТАЕЛЬ

    Принимает:
    login

    Возвращает:
    response: true/false
    """

    try:
        db['users'].find({'login': login})[0]
        if is_valid_login(login):
            return json.dumps(
                {"response": True}
            ), 200
        else:
            return json.dumps({"response": "Логин должен иметь только латинские буквы и цифры, не менее 4 символов и не более 30"}, ensure_ascii=False), 400
    except IndexError:
        if is_valid_login(login):
            return json.dumps(
                {"response": False}
            ), 404
        else:
            return json.dumps({"response": "Логин должен иметь только латинские буквы и цифры, не менее 4 символов и не более 30"}, ensure_ascii=False), 400

@app.route('/api/get_token', methods=['POST'])
def check_login():
    """
    ПРОВЕРКА ВХОДА

    Принимает:
    login, password

    Возвращает:
    response: true/false, token
    """
    j = request.get_json(force=True)

    try:
        j['login']
        j['password']
    except:
        abort(400, 'Эндпоинт принимает: login, password')
    
    try:
        user = db.users.find_one({'login': j['login']})
    except:
        return json.dumps({"response": "Пользователь не найден"}, ensure_ascii=False), 404
    login = user['login']
    password_hash = user['password']

    attempted_password = j['password']

    if not bcrypt.checkpw(attempted_password.encode(), password_hash):
        return json.dumps({"response": "Логин или пароль неверны"}, ensure_ascii=False), 400
        
    today = datetime.date.today()
    three_months_later = today + datetime.timedelta(days=3*30)
    timestamp = three_months_later.strftime("%s")
    token = str(uuid4())
    db['tokens'].insert_one(
        {
            "user_id": db['users'].find_one({'login': j['login']})['id'],
            "token": token,
            "expires": timestamp
        }
    )
    return json.dumps({"response": True, "token": token}, ensure_ascii=False), 200

@app.route('/api/chats/create', methods=['POST'])
def create_chat():
    """
    СОЗДАНИЕ НОВОГО ЧАТА

    Принимает:
    token, chat_name

    Возвращает:
    response: true / <error string>
    """

    j = request.get_json(force=True)

    try:
        j['token']
        j['chat_name']
    except:
        abort(400, 'Эндпоинт принимает: token, chat_name')

    if not is_valid_name(j['chat_name']):
        return json.dumps({"response": "Название чата должно быть не более 30 символов, и не менее 1"}, ensure_ascii=False), 400
    
    try:
        id = db.chats.find().limit(1).sort('id', -1)[0]['id']+1
    except IndexError:
        id = 0

    members = []
    one_member = db.tokens.find_one(
        {'token': j['token']}
    )['user_id']
    members.append(one_member)
        
    db['chats'].insert_one(
            {
                'id': id,
                'name': j['chat_name'], 
                'members': members,
                'creation_date': datetime.datetime.now().timestamp(),
                'type': 'group',
                'avatar': f'https://blazer321.ru/res/ava%20({random.randint(1,16)}).png',
                'messages': [
                    {
                        'id': 0,
                        'user_id': 7,
                        'content': 'Чат создан',
                        'type': 'info',
                        'read': [],
                        'datetime': datetime.datetime.now().timestamp()
                    }
                ]
            }
        )
    
    return json.dumps(
        {"response": True}
    ), 200

@app.route('/api/chats/<chat_id>/send', methods=['POST'])
def send_message(chat_id):
    """
    ОТПРАВКА СООБЩЕНИЯ В ЧАТ

    Принимает:
    chat_id, token, content

    Возвращает:
    response: true / <error string>
    """

    j = request.get_json(force=True)

    chat_id = int(chat_id)

    try:
        j['token']
        j['content']
    except:
        abort(400, 'Эндпоинт принимает: token, content')

    if not is_valid_message(j['content']):
        return json.dumps({"response": "Сообщение должно быть не более 3000 символов"}, ensure_ascii=False), 400
    
    chat = db.chats.find_one({
        'id': chat_id
    })

    one_member = db.tokens.find_one(
        {'token': j['token']}
    )['user_id']

    if one_member in chat['members']:
        try:
            id = chat['messages'][-1]['id']+1
        except IndexError:
            id = 0
    
        chat['messages'].append({
            'id': id,
            'user_id': one_member,
            'content': j['content'],
            'read': [],
            'datetime': datetime.datetime.now().timestamp()
        })
        db.chats.update_one(
            {'id': chat_id}, {
                '$set': {
                    'messages': chat['messages']
                }
            }
        )
        return json.dumps(
            {"response": True}
        ), 200
    else:
        return json.dumps({"response": "У вас нет доступа к этому чату"}, ensure_ascii=False), 403

@app.route('/api/chats/get', methods=['POST'])
def longpool():
    """
    ЛОНГПУЛЛ

    Принимает:
    opened_chat_id, token, client_state

    Возвращает:
    response: true, 
    last_chats: {name, avatar, last_message, new_messages},
    opened_chat_history: none / chat_object
    """

    j = request.get_json(force=True)

    try:
        j['token']
        j['random_client_code']
    except:
        abort(400, 'Эндпоинт принимает: token, random_client_code, [opened_chat_id, client_state]')
    
    try:
        j['opened_chat_id']
        is_chat_opened = True
    except:
        is_chat_opened = False
        opened_chat_history = None
    
    try:
        j['client_state']
    except:
        j['client_state'] = False

    time = datetime.datetime.now()

    connected_clients.append(j['random_client_code'])

    while True:
        one_member = db.tokens.find_one(
            {'token': j['token']}
        )['user_id']

        last_chats = []
        chat_info = None

        for chat in db.chats.find({'members': {'$in': [one_member]}}):
            try:
                last_message = chat['messages'][-1]['content']
                dt = chat['messages'][-1]['datetime']
            except:
                last_message = '<Чат создан>'
                dt = 0
            last_chats.append(
                {
                    "id": chat['id'],
                    "name": chat['name'],
                    "avatar": chat['avatar'],
                    "last_message": last_message,
                    'new_messages': 0,
                    'datetime': dt
                }
            )
        
        if is_chat_opened:
            chat = db.chats.find_one({'id': j['opened_chat_id']})
            try:
                chat['members']
            except:
                abort(404, 'Чата не существует')
                break
            if one_member in chat['members']:
                opened_chat_history = []
                search = chat['messages']#[len(chat['messages'])-15:len(chat['messages'])]
                for message in search:
                    if 'type' in message:
                        pass
                    elif message['user_id'] == one_member:
                        message['type'] = 'me'
                    else:
                        message['type'] = ''
                    message['avatar'] = db.users.find_one({'id': one_member})['avatar']
                    opened_chat_history.append(message)
                chat_info = {
                    'avatar': chat['avatar'],
                    'name': chat['name'],
                    'status': 'Участников: ' + str(len(chat['members'])),
                    'id': chat['id']
                }
            else:
                abort(403, 'Вас нет в этом чате')
                break
        
        resp = {
            "response": True,
            "last_chats": last_chats,
            "opened_chat_history": opened_chat_history,
            "chat_info": chat_info
        }

        try:
            client_state = json.loads(j['client_state'])
        except:
            client_state = j['client_state']

        if resp != client_state:
            print('отправлено '+str(datetime.datetime.now()))
            return json.dumps(resp, ensure_ascii=False), 200

        elif not j['random_client_code'] in connected_clients:
            return json.dumps(
                {"response": True}
            ), 408
            
        elif (datetime.datetime.now() - time).seconds > 60:
            response = Response(status=100)
            response.headers['Expect'] = '100-continue'
            response.direct_passthrough = False
            return response

@app.route('/api/chats/<chat_id>/generate_code', methods=['POST'])
def generate_chat_code_route(chat_id):
    """
    ГЕНЕРАЦИЯ КОДА ЧАТА

    Принимает:
    chat_id, token

    Возвращает:
    response: true / false,
    code: code / undefined
    """

    j = request.get_json(force=True)

    try:
        j['token']
    except:
        abort(400, 'Эндпоинт принимает: token')

    chat_id = int(chat_id)

    chat = db.chats.find_one({
        'id': chat_id
    })

    one_member = db.tokens.find_one(
        {'token': j['token']}
    )['user_id']

    if one_member in chat['members']:
        if one_member == chat['members'][0]:
            symbols_for_chat_code = 5
            code = generate_chat_code(symbols_for_chat_code)
            while not db.chats.find_one({'code': code}, {'code': 1}) is None:
                code = generate_chat_code(symbols_for_chat_code)
                symbols_for_chat_code += 1
            db.chats.update_one({'id': chat_id}, {'$set': {'code': code}})
            msgs = chat['messages']
            try:
                msgs_id = chat['messages'][-1]['id']+1
            except IndexError:
                msgs_id = 0
            msgs.append(
                {
                    'id': msgs_id,
                    'user_id': 7,
                    'content': 'Код чата сгенерирован заного',
                    'type': 'info',
                    'read': [],
                    'datetime': datetime.datetime.now().timestamp()
                }
            )
            db.chats.update_one({'id': chat_id}, {'$set': {'messages': msgs}})
            return json.dumps(
                {"response": True,
                 "code": code}
            ), 200
        else:
            abort(403, 'Вы не создатель чата')
    else:
        abort(403, 'Вас нет в этом чате')

@app.route('/api/chats/<chat_id>/get_code', methods=['POST'])
def get_chat_code_route(chat_id):
    """
    ПОЛУЧЕНИЕ КОДА ЧАТА

    Принимает:
    chat_id, token

    Возвращает:
    response: true / false,
    code: code / 'Нету'
    """

    j = request.get_json(force=True)

    try:
        j['token']
    except:
        abort(400, 'Эндпоинт принимает: token')

    chat_id = int(chat_id)

    chat = db.chats.find_one({
        'id': chat_id
    })

    one_member = db.tokens.find_one(
        {'token': j['token']}
    )['user_id']

    if one_member in chat['members']:
        if not chat is None:
            try:
                return json.dumps(
                    {"response": True,
                    "code": chat['code']}
                ), 200
            except:
                return json.dumps(
                    {"response": True,
                    "code": 'Нету'}
                ), 200
    else:
        abort(403, 'Вас нет в этом чате')

@app.route('/api/chats/close', methods=['POST'])
def close_connections():
    " ЗАКРЫТИЕ СОЕДИНЕНИЙ "

    j = request.get_json(force=True)

    try:
        j['connections']
    except:
        abort(400, 'Эндпоинт принимает: connections')

    for i in j['connections']:
        try:
            connected_clients.remove(i)
        except:
            pass

    return json.dumps(
        {"response": True}
    ), 200

@app.route('/api/chats/<code>/join/', methods=['POST'])
def join_chat_route(code):
    """
    ПОЛУЧЕНИЕ КОДА ЧАТА

    Принимает:
    code, token

    Возвращает:
    response: true / false
    """

    j = request.get_json(force=True)

    try:
        j['token']
    except:
        abort(400, 'Эндпоинт принимает: token')

    chat = db.chats.find_one({
        'code': code
    })

    one_member = db.tokens.find_one(
        {'token': j['token']}
    )['user_id']
    
    try:
        msgs = chat['messages']
        mmbrs = chat['members']
    except:
        abort(403, 'Такого чата нет')

    try:
        msgs_id = chat['messages'][-1]['id']+1
    except IndexError:
        msgs_id = 0
    user = db.users.find_one(
        {'id': one_member}, {'name': 1}
    )['name']

    msgs.append(
        {
            'id': msgs_id,
            'user_id': 7,
            'content': user+' зашёл в чат по коду',
            'type': 'info',
            'read': [],
            'datetime': datetime.datetime.now().timestamp()
        }
    )
    mmbrs.append(one_member)
    db.chats.update_one({'code': code}, {'$set': {'messages': msgs, 'members': mmbrs}})
    return json.dumps(
        {"response": True}
    ), 200

if __name__ == '__main__':
    app.run(debug=False, host="0.0.0.0", port=80, threaded=True)
