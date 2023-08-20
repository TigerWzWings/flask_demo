from flask import Flask, request, url_for, redirect, flash
from flask import render_template
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import os
import sys
import click

WIN = sys.platform.startswith('win') # 平台兼容性适配
if WIN:
    prefix = 'sqlite:///'
else:
    prefix = 'sqlite:////'

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = prefix + os.path.join(app.root_path, 'data.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
app.config['SECRET_KEY'] = 'dev'
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@app.cli.command()
@click.option('--drop', is_flag=True, help='Create after drop.')
def initdb(drop):
    """Initialize the database"""
    if drop:
        db.drop_all()
    db.create_all()
    click.echo('Initialized database')

@app.route('/hello')
def hello_world():
    return 'My first demo to learn Flask.Hello_wolrd!'

@app.cli.command()
@click.option('--username', prompt=True, help='The username for login')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True, help='The password to login')
def admin(username, password):
    """create a user"""
    db.create_all()

    user = User.query.first()
    if user is not None:
        click.echo('Updating user...')
        user.username = username
        user.set_password(password)
    else:
        click.echo('Creating a user...')
        user = User(username=username, name='Admin')
        user.set_password(password)
        db.session.add(user)
    db.session.commit()
    click.echo('Done! ')

@login_manager.user_loader
def load_user(user_id):   # 需要创建一个【用户回调函数】， 接受用户ID作为参数，以作为主键查询对应的用户
    user = User.query.get(int(user_id))
    return user


@app.cli.command()
def forge():
    """generate data."""
    db.create_all()
    name = 'zhao'
    movies = [
        {'title': 'My Neighbor Totoro', 'released_time': '1988'},
        {'title': 'Dead Poets Society', 'released_time': '1989'},
        {'title': 'A Perfect World', 'released_time': '1993'},
        {'title': 'Leon', 'released_time': '1994'},
        {'title': 'Mahjong', 'released_time': '1996'},
        {'title': 'Swallowtail Butterfly', 'released_time': '1996'},
        {'title': 'King of Comedy', 'released_time': '1999'},
        {'title': 'Devils on the Doorstep', 'released_time': '1999'},
        {'title': 'WALL-E', 'released_time': '2008'},
        {'title': 'The Pork of Music', 'released_time': '2012'},
    ]
    user = User(name=name)
    db.session.add(user)
    for m in movies:
        movie = Movie(title=m['title'], released_time=m['released_time'])
        db.session.add(movie)
    db.session.commit()
    click.echo('Done.')

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)  # 主键
    name = db.Column(db.String(20))
    username = db.Column(db.String(20))
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def validate_password(self, password):
        return check_password_hash(self.password_hash, password)

class Movie(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # 主键
    title = db.Column(db.String(60))
    released_time = db.Column(db.String(4))
    director = db.Column(db.String(60))



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('Invalid Input')
            return redirect(url_for('Login'))

        user = User.query.filter_by(username=username).first()
        if not user:
            flash('No exist user')
            return redirect(url_for('registation'))

        if username == user.username and user.validate_password(password):
            login_user(user)  # 登入用户
            flash('Login success.')
            return redirect(url_for('index'))  # 重定向到主页

        flash('Invalid username or password.')  # 如果验证失败，显示错误消息
        return redirect(url_for('login'))  # 重定向回登录页面
    return render_template('login.html')

@app.route('/logout')
@login_required    # 用于视图保护
def logout():
    logout_user()   # 登出用户
    flash('Bye Bye.')
    return redirect(url_for('index'))

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        name = request.form['name']

        if not name or len(name) > 20:
            flash('Invalid input.')
            return redirect(url_for('settings'))

        current_user.name = name
        # current_user 会返回当前登录用户的数据库记录对象
        # 等同于下面的用法
        # user = User.query.first()
        # user.name = name
        db.session.commit()
        flash('Settings updated.')
        return redirect(url_for('index'))

    return render_template('settings.html')


@app.route('/registation', methods=['GET', 'POST'])
def registation():
    if request.method == 'POST':
        name = request.form.get('username')
        password = request.form.get('password')
        if not User.query.filter_by(username=name).first():
            new_user = User(name=name, username=name, password_hash=generate_password_hash(password))

            db.session.add(new_user)
            db.session.commit()
            flash("Success registed! Let's note some movies.")
            return redirect(url_for('login'))
        else:
            flash("User already exists!")

    return render_template('registation.html')


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':  # 判断是否是 POST 请求
        if not current_user.is_authenticated:   # 登录验证
            return redirect(url_for('index'))
        # 获取表单数据
        title = request.form.get('title')  # 传入表单对应输入字段的 name 值
        year = request.form.get('released_time')
        director_name = request.form.get('director')

        # 验证数据
        if not title or not year or len(year) > 4 or len(title) > 60 or len(director_name)>60:
            flash('Invalid input.')  # 显示错误提示
            return redirect(url_for('index'))  # 重定向回主页
        # 保存表单数据到数据库
        movie = Movie(title=title, released_time=year, director=director_name if director_name is not None else None)  # 创建记录
        db.session.add(movie)  # 添加到数据库会话
        db.session.commit()  # 提交数据库会话
        flash('Item created.')  # 显示成功创建的提示
        return redirect(url_for('index'))  # 重定向回主页

    movies = Movie.query.all()
    return render_template('index.html', movies=movies)

@app.route('/movie/edit/<int:movie_id>', methods=['GET', 'POST'])
@login_required
def edit(movie_id):
    movie = Movie.query.get_or_404(movie_id)
    if request.method == 'POST':
        title = request.form['title']
        year = request.form['released_time']
        if not title or not year or len(year)>8 or len(title)>=60:
            flash('Invalid input.')
            return redirect(url_for('edit', movie_id=movie_id))

        movie.title = title
        movie.released_time = year
        db.session.commit()
        flash('Item Update')
        return redirect(url_for('index'))
    return render_template('edit.html', movie=movie)

@app.route('/movie/delete/<int:movie_id>', methods=['POST'])
@login_required
def delete(movie_id):
    movie = Movie.query.get_or_404(movie_id)
    db.session.delete(movie)
    db.session.commit()
    flash('Item deleted.')
    return redirect(url_for('index'))

@app.context_processor
def inject_user():
    user = User.query.first()
    return dict(user=user)

@app.errorhandler(404)
def page_not_found(e):
    user = User.query.first()
    #return render_template('404.html', user=user), 404
    return render_template('404.html'), 404
