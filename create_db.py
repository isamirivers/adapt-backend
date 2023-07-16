try:
    import pymongo
except:
    print('Install pymongo!')
    exit()

client = pymongo.MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=1)

try:
    client.server_info()
except pymongo.errors.ServerSelectionTimeoutError as err:
    print('Фатальная ошибка: Не могу подключиться к базе данных.')
    exit()

db = client["adapt"]

def create_table(name):
    collection = db[name]
    collection.insert_one({"test": "test"})
    collection.delete_one({"test": "test"})

create_table('users')
create_table('conversations')
create_table('messages')
create_table('contacts')
create_table('attachments')

print('MongoDB tables created!')
