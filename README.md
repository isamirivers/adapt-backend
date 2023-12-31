# Adapt Backend
Backend for [quinque1337/adapt-app](https://github.com/quinque1337/adapt-app)

Adapt is a side-project messenger that we were working on in college, but it has a lot of bugs and is not yet ready for production purposes :^

You can help us make it production-ready by contributing to our code. We would be extremely grateful!
## We are hosting it
If you want to just use it on our instance, you can check [Adapt Web](https://blazer321.ru/web) and [Adapt API](https://blazer321.ru/) that we are hosting. Sadly, there is no documentation for API at this moment.
## How to run
- Install [MongoDB Community Server](https://www.mongodb.com/try/download/community) (we use 4.4.21)
- Clone this repo
- Run `pip install -r requirements.txt`
- Start MongoDB with the command `sudo mongod --fork --logpath /var/log/mongodb/mongod.log`
- Start the server with `sudo gunicorn --workers=5 --threads=4 --daemon --bind 0.0.0.0:80 wsgi:app`
- Use [quinque1337/adapt-app](https://github.com/quinque1337/adapt-app) to use messenger
- If you encounter any issues, please don't hesitate to add them to the [issues](https://github.com/isamirivers/adapt-backend/issues) section.

Thank you for your attention!
