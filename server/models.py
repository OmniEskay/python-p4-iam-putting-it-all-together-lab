from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    # Serialization rules to prevent recursion
    serialize_rules = ('-recipes.user',)

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    _password_hash = db.Column(db.String, nullable=False)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    # Relationship to Recipe
    recipes = db.relationship('Recipe', back_populates='user', cascade='all, delete-orphan')

    @hybrid_property
    def password_hash(self):
        """
        Prevents direct access to the password hash.
        """
        raise AttributeError('Password hashes may not be viewed.')

    @password_hash.setter
    def password_hash(self, password):
        """
        Hashes and sets the password.
        """
        password_hash = bcrypt.generate_password_hash(
            password.encode('utf-8'))
        self._password_hash = password_hash.decode('utf-8')

    def authenticate(self, password):
        """
        Authenticates a user by checking the provided password against the stored hash.
        """
        return bcrypt.check_password_hash(
            self._password_hash, password.encode('utf-8'))

    @validates('username')
    def validate_username(self, key, username):
        """
        Validates that the username is present.
        """
        if not username:
            raise ValueError("Username must be present.")
        return username

    def __repr__(self):
        return f'<User {self.username}>'


class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'

    # Serialization rules to prevent recursion
    serialize_rules = ('-user.recipes',)

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)

    # Foreign Key to User
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    # Relationship to User
    user = db.relationship('User', back_populates='recipes')

    @validates('title')
    def validate_title(self, key, title):
        """
        Validates that the title is present.
        """
        if not title:
            raise ValueError("Title must be present.")
        return title

    @validates('instructions')
    def validate_instructions(self, key, instructions):
        """
        Validates that instructions are present and are at least 50 characters long.
        """
        if not instructions:
            raise ValueError("Instructions must be present.")
        if len(instructions) < 50:
            raise ValueError("Instructions must be at least 50 characters long.")
        return instructions

    def __repr__(self):
        return f'<Recipe {self.title}>'