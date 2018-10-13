from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class Users(Base):
    __tablename__ = 'Users'

    id = Column(Integer, primary_key=True)
    username = Column(String(250), nullable=False)
    password = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)


class Questions(Base):
    __tablename__ = 'Questions'

    id = Column(Integer, primary_key=True)
    question = Column(String(1000), nullable=False)
    type = Column(String(250), nullable=False)
    mandatory = Column(String(250), nullable=False)
    option1 = Column(String(1000), nullable=True)
    option2 = Column(String(1000), nullable=True)
    option3 = Column(String(1000), nullable=True)
    option4 = Column(String(1000), nullable=True)
    option5 = Column(String(1000), nullable=True)


class Answers(Base):
    __tablename__ = 'Answers'

    id = Column(Integer, primary_key=True)
    choice = Column(String(1000), nullable=False)
    question_id = Column(Integer, ForeignKey('Questions.id'))
    question = relationship(Questions)
    user_id = Column(Integer, ForeignKey('Users.id'))
    user = relationship(Users)


engine = create_engine('sqlite:////vagrant/probate.db')

Base.metadata.create_all(engine)
