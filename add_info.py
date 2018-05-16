
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Category, Base, Item, User

engine = create_engine('sqlite:///catalog.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


category1 = Category(name="Hockey")

session.add(category1)
session.commit()

# Menu for Super Stir Fry
category2 = Category(name="Soccer")

session.add(category2)
session.commit()


# Menu for Panda Garden
category3 = Category(name="Basketball")

session.add(category3)
session.commit()



print "added categories and items!"
