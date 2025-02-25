from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
import time
import random
import os

class KaggleScraper:
    def __init__(self):
        self.options = Options()
        self.options.add_argument("--headless")
        self.options.add_argument("--disable-dev-shm-usage")
        self.options.add_argument('--disable-gpu')
        self.options.add_argument("--no-sandbox")
        self.service = Service(ChromeDriverManager().install())

    def scrape_leaderboard(self, url):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.get(url)
        time.sleep(random.uniform(5, 10))

        usernames = []
        while True:
            new_users = driver.find_elements(By.CSS_SELECTOR, 'a[aria-label*="profile"]')
            current_batch = [u.get_attribute('href').split('/')[-1] for u in new_users]
            usernames += current_batch

            try:
                btn = WebDriverWait(driver, 7).until(
                    EC.element_to_be_clickable((By.XPATH, "//span[contains(text(), 'See')]"))
                )
                driver.execute_script("arguments[0].scrollIntoView(true);", btn)
                btn.click()
                time.sleep(random.uniform(5, 10))
            except:
                break

        driver.quit()

        results = []
        for username in usernames[:300]:
            if len(results) >= 30:
                break
            details = self.scrape_user_details(username)
            # CORRECTED FILTER CONDITION
            if details['linkedin'] != "N/A" or len(details['websites']) > 0:
                results.append(details)

        return results

    def scrape_user_details(self, username):
        driver = webdriver.Chrome(service=self.service, options=self.options)
        driver.get(f"https://www.kaggle.com/{username}")
        time.sleep(random.uniform(5,8))

        soup = BeautifulSoup(driver.page_source, 'html.parser')
        driver.quit()

        name_tag = soup.find('h1', {'class': 'sc-hBEYId'})
        name = name_tag.get_text(strip=True) if name_tag else username
        bio_tag = soup.find('div', {'class': 'sc-ePpfBx'})

        linkedin = "N/A"
        websites = []
        for link in soup.find_all('a', href=True):
            href = link['href']
            if "linkedin.com/in" in href:
                linkedin = href
            elif "http" in href and "kaggle.com" not in href:
                websites.append(href)

        return {
            'username': username,
            'name': name,
            'bio': bio_tag.get_text(" ", strip=True) if bio_tag else "N/A",
            'linkedin': linkedin,
            'websites': websites
        }
