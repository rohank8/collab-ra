import requests
import logging
import time
import re
import base64
from bs4 import BeautifulSoup
from decouple import config
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote
import os

logging.basicConfig(level=logging.INFO)

class GitHubSearch:
    def __init__(self):
        self.token = os.environ.get("GITHUB_TOKEN", "")
        print(f"DEBUG: GITHUB_TOKEN is {self.token[:6]}...")
        self.headers = {'Authorization': f'token {self.token}'}
        self.base_api = 'https://api.github.com'
        self.max_workers = 4
        self.request_timeout = 30
        self.rate_limit_reset = 0
        self.results_per_page = 10
        self.max_repos_check = 3
        self.profile_search_limit = 5

    def search_users(self, raw_query, page=1):
        try:
            start_time = time.time()
            processed_query = self._process_query(raw_query)
            base_keywords = self._extract_search_terms(raw_query)

            profile_users = self._search_profile_matches(processed_query)

            analyzed_users = []
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = [executor.submit(self._quick_analyze_user, u['login'], base_keywords)
                          for u in profile_users]

                for future in as_completed(futures):
                    if (time.time() - start_time) > 290:
                        logging.warning("Approaching timeout - partial results")
                        break
                    if user_data := future.result():
                        analyzed_users.append(user_data)

            sorted_users = sorted(analyzed_users, key=lambda x: x['score'], reverse=True)
            return self._paginate_results(sorted_users, page)

        except Exception as e:
            logging.error(f"Search failed: {str(e)}")
            return {'results': [], 'total': 0, 'page': 1, 'total_pages': 0}
        finally:
            logging.info(f"Search completed in {time.time()-start_time:.2f}s")

    def _quick_analyze_user(self, username, keywords):
        try:
            profile = self._safe_get(f'{self.base_api}/users/{username}')
            if not profile:
                return None

            repos = self._safe_get(
                f'{self.base_api}/users/{username}/repos',
                params={'sort': 'updated', 'per_page': self.max_repos_check}
            ) or []

            matching_repos = []
            for repo in repos:
                content = f"{repo['name']} {repo.get('description', '')}".lower()
                matches = [kw for kw in keywords if kw in content]
                if matches:
                    matching_repos.append({
                        'name': repo['name'],
                        'url': repo['html_url'],
                        'matches': list(set(matches))
                    })

            social = self._scrape_social_info(username)

            return {
                'username': username,
                'name': profile.get('name'),
                'bio': profile.get('bio'),
                'location': profile.get('location'),
                'profile_url': profile['html_url'],
                'avatar_url': profile.get('avatar_url', ''),
                'linkedin': social['linkedin'],
                'websites': social['websites'],
                'emails': social['emails'],
                'matching_repos': matching_repos,
                'score': self._calculate_score(social, matching_repos)
            }

        except Exception as e:
            logging.error(f"Analysis failed for {username}: {str(e)}")
            return None

    def _search_profile_matches(self, query):
        users = []
        for page in range(1, self.profile_search_limit + 1):
            response = self._safe_get(
                f'{self.base_api}/search/users',
                params={'q': query, 'per_page': 30, 'page': page}
            )
            if not response:
                break
            users.extend(response.get('items', []))
            time.sleep(1)
        return users

    def _paginate_results(self, results, page):
        start = (page - 1) * self.results_per_page
        end = start + self.results_per_page
        return {
            'results': results[start:end],
            'total': len(results),
            'page': page,
            'total_pages': (len(results) + self.results_per_page - 1) // self.results_per_page
        }

    def _calculate_score(self, social, repos):
        score = 7 if social['linkedin'] else 0
        score += 2 * len(social['websites'])
        score += 1 * len(social['emails'])
        score += sum(len(repo['matches']) for repo in repos)
        return score

    def _scrape_social_info(self, username):
        try:
            response = requests.get(
                f"https://github.com/{username}",
                timeout=self.request_timeout
            )
            soup = BeautifulSoup(response.text, 'html.parser')

            return {
                'linkedin': self._find_linkedin(soup),
                'websites': self._find_websites(soup),
                'emails': self._find_emails(soup)
            }
        except Exception:
            return {'linkedin': None, 'websites': [], 'emails': []}

    def _find_linkedin(self, soup):
        link = soup.find('a', href=re.compile(r'linkedin\.com/in/'))
        return self._clean_url(link['href']) if link else None

    def _find_websites(self, soup):
        return [
            self._clean_url(a['href'])
            for a in soup.select('a[rel="nofollow me"]')
            if 'linkedin' not in a['href']
        ][:3]

    def _find_emails(self, soup):
        bio = soup.select_one('.user-profile-bio')
        bio_text = bio.text if bio else ''
        return list(set(re.findall(
            r'\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b',
            bio_text
        )))[:3]

    def _clean_url(self, url):
        return url if url.startswith(('http://', 'https://')) else f'https://{url}'

    def _safe_get(self, url, params=None):
        for _ in range(3):
            if time.time() < self.rate_limit_reset:
                wait = self.rate_limit_reset - time.time() + 1
                logging.info(f"Waiting {wait:.1f}s for rate limit reset")
                time.sleep(wait)

            try:
                response = requests.get(
                    url,
                    headers=self.headers,
                    params=params,
                    timeout=self.request_timeout
                )

                if response.status_code == 403:
                    reset_time = int(response.headers.get('X-RateLimit-Reset', time.time() + 60))
                    self.rate_limit_reset = reset_time
                    wait = max(reset_time - time.time() + 1, 1)
                    logging.warning(f"Rate limit hit. Waiting {wait:.1f}s")
                    time.sleep(wait)
                    continue

                if response.status_code == 200:
                    return response.json()

                return None

            except requests.exceptions.RequestException as e:
                logging.error(f"Request failed: {str(e)}")
                time.sleep(2)
        return None

    def _process_query(self, raw_query):
        processed = re.sub(r'\s*\+\s*', ' ', raw_query)
        processed = re.sub(r'(\b\w+\b)\s+OR\s+(\b\w+\b)', r'\1 OR \2', processed)
        pattern = r'[^\w\s:\+OR_\-\"@]'
        return re.sub(pattern, '', processed).strip()

    def _extract_search_terms(self, raw_query):
        terms = []
        for part in re.findall(r'"([^"]*)"|(\\S+)', raw_query):
            term = part[0] or part[1]
            if ':' not in term and term not in ['OR', 'AND']:
                terms.append(term.lower())
        return list(set(terms))
