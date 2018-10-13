from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime

from database_setup import Base, Users, Questions, Answers

engine = create_engine('sqlite:////vagrant/probate.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

names=['joshbriand', 'adambriand', 'laurawhite']
passwords=['joshbriand', 'adambriand', 'laurawhite']
emails=['joshbriand@gmail.com', 'adam@briandfamily.com', 'laura@briandfamily.com']

users = session.query(Users)
usernames = []
for user in users:
    usernames.append(user.username)

for x in range(0,len(names)):
    if names[x] in usernames:
        print names[x] + " exists already"
    else:
        newUser = Users(username=names[x], password=passwords[x], email=emails[x])
        session.add(newUser)
        session.commit()
        print names[x] + " added"

newUser = Users(username="admin", password="admin", email="adam@briandfamily.com")
session.add(newUser)
session.commit()
print "Added admin user"
