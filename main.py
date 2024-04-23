from flask import Flask, render_template, request
from scanner import get_security_headers, validate_url, get_ip_address, get_ssl_info, fetch_and_parse_robots, fetch_security_txt,calculate_security_grade
from flask_limiter import Limiter
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
limiter = Limiter(app, default_limits=["50 per minute"])
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///search_history.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

@app.route('/about')
def about():
    return render_template('about.html')  

class SearchHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    grade = db.Column(db.Integer, nullable=True)

    def __repr__(self):
        return f'<SearchHistory {self.url} {self.grade}>'
    
@app.cli.command('init-db')
def init_db():
    db.create_all()
    print('Initialized the database.')


@app.route('/', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def index():
    recent_searches = SearchHistory.query.order_by(SearchHistory.timestamp.desc()).limit(10).all()
    show_recent_searches = False 

    if request.method == 'POST':
        input_url = request.form.get('url')
        valid_url = validate_url(input_url)
        if valid_url == '404.html':
            return render_template('404.html'), 404
        else:
            show_recent_searches = True
            present_headers, absent_headers, raw_headers = get_security_headers(valid_url)
            ip_address = get_ip_address(valid_url)
            ssl_info = get_ssl_info(valid_url.split('//')[-1].split('/')[0])  
            robots_data = fetch_and_parse_robots(valid_url)
            security_text = fetch_security_txt(valid_url.split('//')[-1].split('/')[0]) 
            new_search = SearchHistory(url=valid_url, timestamp=datetime.utcnow())
            robots_exists = bool(robots_data)
            security_exists = bool(security_text)
    

            grade = calculate_security_grade(present_headers, ssl_info, robots_exists, security_exists)

            new_search = SearchHistory(url=valid_url, timestamp=datetime.utcnow(), grade=grade)
            db.session.add(new_search)
            db.session.commit()
            


            return render_template('index.html',
                                   present_headers=present_headers,
                                   absent_headers=absent_headers,
                                   raw_headers=raw_headers,
                                   site=valid_url,
                                   show_recent_searches=show_recent_searches,
                                   time=datetime.now().strftime("%Y-%m-%d"),
                                   ip_address=ip_address,
                                   ssl_info=ssl_info,
                                   robots_data=robots_data,
                                   security_text=security_text,
                                   recent_searches=recent_searches,
                                   grade=grade)
                                   
    return render_template('index.html', show_recent_searches=show_recent_searches, recent_searches=recent_searches)

if __name__ == '__main__':
    app.run(debug=True)
