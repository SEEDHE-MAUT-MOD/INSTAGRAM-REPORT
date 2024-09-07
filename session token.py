import requests
from user_agent import generate_user_agent
import time
import os
from colorama import Fore, Back, Style, init

# Initialize colorama
init()

tok = input(Back.RED + 'ENTER YOUR token Bot : ')
io = input(Back.YELLOW + 'ENTER YOUR ID : ')
os.system('clear')

email = input(Back.RED + 'ENTER YOUR Username or Email IG : ')
psw = input(Back.GREEN + 'ENTER YOUR Password : ')

url = 'https://www.instagram.com/api/v1/web/accounts/login/ajax/'
headers = {
    'accept': '*/*',
    'accept-encoding': 'gzip, deflate, br',
    'accept-language': 'en-US,en;q=0.9',
    'content-type': 'application/x-www-form-urlencoded',
    'origin': 'https://www.instagram.com',
    'referer': 'https://www.instagram.com/',
    'user-agent': generate_user_agent(),
    'x-requested-with': 'XMLHttpRequest',
}

# First, we need to get the CSRF token from Instagram
response = requests.get("https://www.instagram.com/accounts/login/")
csrf_token = response.cookies.get('csrftoken')

# Update headers with CSRF token
headers['x-csrftoken'] = csrf_token

timestamp = str(time.time()).split('.')[0]
data = {
    'enc_password': f'#PWD_INSTAGRAM_BROWSER:0:{timestamp}:{psw}',
    'username': email,
    'queryParams': '{}',
    'optIntoOneTap': 'false'
}

# Make the POST request to login
response = requests.post(url, headers=headers, data=data)

if response.status_code == 200 and "userId" in response.text:
    session_id = response.cookies.get("sessionid", "No session ID found")
    print(f'Your Session ID Instagram >> {session_id}')
    tlg = f'''
    Your Session ID >> {session_id}
    BY >> @Haxkx
    '''
    requests.get(f"https://api.telegram.org/bot{tok}/sendMessage?chat_id={io}&text={tlg}")
    print(tlg)
    with open("Meow.txt", "a") as file:
        file.write(f"Your Session >> {session_id}\n")
else:
    print("Login failed:", response.text)
