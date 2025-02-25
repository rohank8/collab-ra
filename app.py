from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from kaggle_search import KaggleScraper
from github_search import GitHubSearch
from pyngrok import ngrok
from concurrent.futures import ThreadPoolExecutor
import os
import uuid
import time

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'
auth = HTTPBasicAuth()

# Configure for Ngrok
app.config['PREFERRED_URL_SCHEME'] = 'https'
app.config['SERVER_NAME'] = 'localhost:5000'

# Background task setup
executor = ThreadPoolExecutor(4)
jobs = {}

# Security headers middleware
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "frame-ancestors 'self' https://*.googleusercontent.com"
    response.headers['X-Frame-Options'] = 'ALLOW-FROM https://colab.research.google.com'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

users = {
    "admin": generate_password_hash(os.getenv('ADMIN_PASSWORD', 'securepassword123'))
}

@auth.verify_password
def verify_password(username, password):
    return username == "admin" and check_password_hash(users["admin"], password)

@app.route('/')
@auth.login_required
def index():
    return render_template('index.html')

@app.route('/search/github', methods=['GET'])
@auth.login_required
def github_search():
    try:
        search_term = request.args.get('q', '').strip()
        page = int(request.args.get('page', 1))

        if not search_term:
            flash('Please enter a search term', 'warning')
            return redirect(url_for('index'))

        searcher = GitHubSearch()
        results = searcher.search_users(search_term, page)

        if results['total_pages'] > page:
            for next_page in range(page + 1, min(page + 3, results['total_pages'] + 1)):
                searcher.search_users(search_term, next_page)

        return render_template('github_results.html',
                            results=results,
                            search_term=search_term)

    except Exception as e:
        flash(f'Search failed: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.route('/search/kaggle', methods=['POST'])
@auth.login_required
def kaggle_search():
    try:
        url = request.form['url']
        job_id = str(uuid.uuid4())

        # Prevent duplicate submissions
        if any(job['url'] == url and job['status'] in ('queued', 'running')
               for job in jobs.values()):
            flash('This URL is already being processed', 'info')
            return redirect(url_for('index'))

        # Initialize job tracking
        jobs[job_id] = {
            'future': executor.submit(KaggleScraper().scrape_leaderboard, url),
            'status': 'queued',
            'start_time': time.time(),
            'url': url,
            'result': None,
            'error': None
        }

        return render_template('loading.html', job_id=job_id)

    except Exception as e:
        flash(f'Scraping failed: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.route('/check_status')
def check_status():
    job_id = request.args.get('job_id')
    job = jobs.get(job_id)

    if not job:
        return jsonify({'status': 'not_found'}), 404

    if job['future'].done():
        try:
            job['result'] = job['future'].result()
            job['status'] = 'completed'
        except Exception as e:
            job['error'] = str(e)
            job['status'] = 'failed'

    return jsonify({
        'status': job['status'],
        'result_available': job['status'] == 'completed',
        'error': job['error']
    })

@app.route('/search/kaggle/results')
def kaggle_results():
    job_id = request.args.get('job_id')
    job = jobs.get(job_id)

    if not job or job['status'] != 'completed':
        flash('Results not available or expired', 'warning')
        return redirect(url_for('index'))

    return render_template('kaggle_results.html',
                         users=job['result'],
                         search_term="Kaggle Leaderboard")

# Expose the app to the internet using ngrok
ngrok.set_auth_token("2tRnHsZCARZ9SUabqPEIEYTOmW2_63JNxNvKAEpGQY1h5cFXB")
public_url = ngrok.connect(5000)
print(f' * ngrok tunnel "{public_url}" -> "http://127.0.0.1:5000"')

if __name__ == '__main__':
    app.run(port=5000, threaded=True)
