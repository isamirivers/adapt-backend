sudo pkill nginx
sudo mongod --fork --logpath /var/log/mongodb/mongod.log
sudo gunicorn --workers=5 --threads=4 --daemon --bind 0.0.0.0:80 wsgi:app
