from db import db
from db.models import users, product, cartitem
from flask_login import login_user, login_required, current_user, logout_user, LoginManager
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
import re

app = Flask(__name__)

app.secret_key = "123"
user_db = "unus"
host_ip = "127.0.0.1"
host_port = "5432"
database_name = "rgz_unus"
password="123"

app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{user_db}:{password}@{host_ip}:{host_port}/{database_name}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

login_manager = LoginManager(app)

login_manager.login_view = "login"
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return users.query.get(int(user_id))


# Главная страница   
@app.route('/')
def home():
    products = product.query.all()
    if 'user_id' in session:
        user = users.query.get(session['user_id'])
        cart_items = user.cart
        return render_template('index.html', products=products, cart_items=cart_items)
    else:
        return render_template('index.html', products=products)


@app.route('/add_to_cart/<int:product_id>')
@login_required
def add_to_cart(product_id):
    if current_user.is_authenticated:
        cart_item = cartitem(product_id=product_id, user_id = current_user.id)
        db.session.add(cart_item)
        db.session.commit()
        return redirect('/')


@app.route('/cart')
@login_required
def view_cart():
    user = current_user.id
    grouped_items = {}
    cart_items = cartitem.query.filter_by(user_id=user).all()
    
    for item in cart_items:
        product_item = product.query.get(item.product_id)  # Получите объект товара по ID

        if product_item.id in grouped_items:
            grouped_items[product_item.id]['count'] += 1
            grouped_items[product_item.id]['price'] + product_item.price
        else:
            grouped_items[product_item.id] = {
                'name': product_item.name,
                'count': 1,
                'price': product_item.price  # Добавьте цену товара в словарь
            }

    total_cost = round(sum(item['price'] * item['count'] for item in grouped_items.values()), 2)
    return render_template('cart.html', grouped_items=grouped_items, cart_items = cart_items, total_cost=total_cost)


@app.route('/remove_from_cart/<int:item_id>')
@login_required
def remove_from_cart(item_id):
    user = users.query.get(current_user.id)
    cart_item = cartitem.query.get(item_id)
    if cart_item.user_id == user.id:
        db.session.delete(cart_item)
        db.session.commit()
    return redirect('/cart')


@app.route('/checkout')
@login_required
def checkout():
    if current_user.is_authenticated:
        user_id = current_user.id

        cart_items = cartitem.query.filter_by(user_id=user_id).all()
        total_cost = 0  # Инициализируйте переменную для подсчета общей стоимости

        for item in cart_items:
            product_ = product.query.get(item.product_id)
            total_cost += product_.price  # Добавьте стоимость товара к общей стоимости
            db.session.delete(item)

        db.session.commit()
        return redirect('/payment')


@app.route('/payment', methods=['GET', 'POST'])
@login_required
def payment():
    if request.method == 'POST':
        card_number = request.form['card_number']
        expiration_date = request.form['expiration_date']
        cvv = request.form['cvv']
    
    total_cost = 0
    user_id = current_user.id
    cart_items = cartitem.query.filter_by(user_id=user_id).all()
    
    for item in cart_items:
        product_ = product.query.get(item.product_id)
        total_cost += product_.price
        
    return render_template('payment.html', total_cost=total_cost)


@app.route('/congrats', methods=['GET', 'POST'])
@login_required
def congrats():
    return render_template('suc.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "GET":
        return render_template("register.html")
    
    username_form = request.form.get("username")
    password_form = request.form.get("password")

    isUserExist = users.query.filter_by(username = username_form).first()

    errors = []

    if isUserExist is not None:
        errors.append("Такой пользователь уже существует!")
        return render_template("register.html", errors=errors)
    elif not username_form:
        errors.append("Введите имя пользователя!")
        return render_template("register.html", errors=errors)
    elif not re.match("^[a-zA-Z0-9]+$", password_form):  # Проверка на наличие только букв и цифр
        errors.append("Пароль должен содержать только буквы и цифры!")
        return render_template("register.html", errors=errors)
    elif re.search("[а-яА-Я]", password_form):  # Проверка на наличие русских символов
        errors.append("Пароль не должен содержать русские буквы!")
        return render_template("register.html", errors=errors)
    elif len(password_form) < 5:
        errors.append("Пароль должен содержать не менее 5 символов!")
        return render_template("register.html", errors=errors)

    hashedPswd = generate_password_hash(password_form, method="pbkdf2")

    newUser = users(username = username_form, password = hashedPswd)

    db.session.add(newUser)

    db.session.commit()

    return redirect("/login")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "GET":
        return render_template("login.html")
    
    if current_user.is_authenticated:  # Если пользователь уже авторизован, перенаправляем его на другую страницу
        return redirect('/')

    if request.method == "POST":
        errors = []
        username_form = request.form.get("username")
        password_form = request.form.get("password")

        my_user = users.query.filter_by(username=username_form).first()

        if my_user is not None:
            if check_password_hash(my_user.password, password_form):
                login_user(my_user, remember=False)
                return redirect('/')

        if not (username_form or password_form):
            errors.append("Введите имя пользователя и пароль!")
        elif my_user is None or not check_password_hash(my_user.password, password_form):
            errors.append("Неверное имя пользователя или пароль!")

        return render_template("login.html", errors=errors)

    return render_template("login.html")

# Страница выхода из системы
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')
