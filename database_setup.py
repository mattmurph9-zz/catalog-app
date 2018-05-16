import sys
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
import datetime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class User(Base):
	__tablename__ = 'user'

	name = Column(String(80), nullable = False)
	email = Column(String(80), nullable = False)
	picture = Column(String(80), nullable = False)
	uid = Column(Integer, primary_key = True)

class Category(Base):
	__tablename__ = 'category'

	name = Column(String(80), primary_key = True)
	#id = Column(Integer, primary_key = True)

class Item(Base):
	__tablename__ = 'item'
	name = Column(String(80), primary_key = True)
	#id = Column(Integer, primary_key = True)
	description = Column(String(250))
	date = Column(DateTime, default=datetime.datetime.utcnow)
	category_name = Column(String(80), ForeignKey('category.name'))
	category = relationship(Category)
	uid = Column(Integer, ForeignKey('user.uid'))
	user = relationship(User)

	
engine = create_engine('sqlite:///catalog.db')

Base.metadata.create_all(engine)
