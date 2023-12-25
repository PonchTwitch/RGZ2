from werkzeug.security import generate_password_hash, check_password_hash
from . import db

# Определите модели данных
class users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    password = db.Column(db.String(200))
    cart = db.relationship('cartitem', backref='user', lazy=True)

    def is_authenticated(self):
    # Возвращает True, если пользователь аутентифицирован
        return True

class product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80))
    price = db.Column(db.Float)
    photo = db.Column(db.Text)
    description = db.Column(db.Text)

class cartitem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
