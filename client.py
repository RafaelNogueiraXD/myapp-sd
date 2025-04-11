import os
import requests
import time

SERVER_URL = os.getenv('SERVER_URL')

while True:
    try:
        response = requests.get(SERVER_URL)
        print(f"Client {os.getenv('HOSTNAME')} received: {response.text}")
    except Exception as e:
        print(f"Error contacting server: {e}")
    time.sleep(3)