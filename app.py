"""
This script defines a Flask application that provides URL shortening functionality.
It uses Google Cloud Firestore as the database for storing the shortened URLs.
The application also includes various utility functions for checking API keys, 
checking URLs against Google Safe Browsing API, retrieving page titles, and generating 
new emoji string IDs for shortened URLs.

The main routes of the application include:
- GET /: Returns the index.html file from the "static" directory.
- GET /privacy: Redirects the user to the privacy policy page.
- POST /: Shortens a given URL and returns a shortened URL.
- GET /<url_id>: Redirects to the specified URL based on the given URL ID.

The application uses various external libraries such as Flask, BeautifulSoup, 
requests, emoji, and Google Cloud libraries for Secret Manager and Firestore.

Note: This script requires proper configuration of Google Cloud services and 
API keys for Google Safe Browsing and Secret Manager.
"""

import itertools
import os
import random
from functools import wraps
from urllib.parse import urlparse
import emoji
import requests
import validators
from bs4 import BeautifulSoup
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from google.cloud import secretmanager

from google.cloud import firestore
from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
)


app = Flask(__name__)
app.config.update(
    dict(
        PREFERRED_URL_SCHEME="https",
        SESSION_COOKIE_SECURE=True,
        REMEMBER_COOKIE_SECURE=True,
    )
)
ALLOWED_ORIGINS = [
    "https://thayn-cc.uc.r.appspot.com",
    "https://thayn.cc",
    "https://www.thayn.cc",
    "https://fonts.googleapis.com/",
]
CSP = {
    "default-src": ["'self'"],
    "img-src": ["'self'", "data:", "https://www.w3.org/"],
    "style-src": ["'self'", "https://fonts.googleapis.com/", "'unsafe-inline'"],
    "font-src": ["https://fonts.gstatic.com/"],
    "script-src": ["'self'", "'unsafe-inline'"],
}

cors = CORS(app, resources={r"/*": {"origins": ALLOWED_ORIGINS}})
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per hour", "1000 per day"],
    storage_uri="memory://",
    strategy="moving-window",
)
talisman = Talisman(app, content_security_policy=CSP)

# Fetch Google API key for Safe Browsing
client = secretmanager.SecretManagerServiceClient()
PROJECT_ID = "358507212056"
name = f"projects/{PROJECT_ID}/secrets/google_safe_browsing/versions/latest"
GOOGLE_API_KEY = client.access_secret_version(
    request={"name": name}
).payload.data.decode("UTF-8")

# Define a dictionary of valid API keys
client = secretmanager.SecretManagerServiceClient()
PROJECT_ID = "358507212056"
secrets = ["Cyan", "Meghan"]
valid_api_keys = {}
for secret_id in secrets:
    name = f"projects/{PROJECT_ID}/secrets/{secret_id}/versions/latest"
    response = client.access_secret_version(request={"name": name})
    valid_api_keys[response.payload.data.decode("UTF-8")] = secret_id

# Define a list of URL-safe emoji
emojis = [
    ":grinning_face:",
    ":grinning_face_with_big_eyes:",
    ":grinning_face_with_smiling_eyes:",
    ":beaming_face_with_smiling_eyes:",
    ":grinning_squinting_face:",
    ":grinning_face_with_sweat:",
    ":rolling_on_the_floor_laughing:",
    ":face_with_tears_of_joy:",
    ":slightly_smiling_face:",
    ":upside-down_face:",
    ":winking_face:",
    ":smiling_face_with_smiling_eyes:",
    ":smiling_face_with_halo:",
    ":relieved_face:",
    ":pensive_face:",
    ":face_screaming_in_fear:",
    ":frowning_face_with_open_mouth:",
    ":anguished_face:",
    ":fearful_face:",
    ":weary_face:",
    ":sleepy_face:",
    ":tired_face:",
    ":grimacing_face:",
    ":loudly_crying_face:",
    ":face_with_medical_mask:",
    ":face_with_thermometer:",
    ":smiling_face_with_sunglasses:",
    ":nerd_face:",
    ":face_with_monocle:",
    ":astonished_face:",
    ":flushed_face:",
    ":pleading_face:",
    ":broken_heart:",
    ":red_heart:",
    ":orange_heart:",
    ":yellow_heart:",
    ":green_heart:",
    ":blue_heart:",
    ":purple_heart:",
    ":brown_heart:",
    ":black_heart:",
    ":white_heart:",
    ":anger_symbol:",
    ":collision:",
    ":dizzy:",
    ":sweat_droplets:",
    ":dashing_away:",
    ":hole:",
    ":bomb:",
    ":speech_balloon:",
    ":left_speech_bubble:",
    ":right_anger_bubble:",
    ":thought_balloon:",
    ":thumbs_up:",
    ":thumbs_down:",
    ":open_hands:",
    ":handshake:",
    ":writing_hand:",
    ":nail_polish:",
    ":selfie:",
    ":mechanical_arm:",
    ":leg:",
    ":foot:",
    ":ear:",
    ":nose:",
    ":brain:",
    ":tooth:",
    ":bone:",
    ":eyes:",
    ":tongue:",
]
for i, emoji_name in enumerate(emojis):
    emojis[i] = emoji.emojize(emoji_name)

# Initialize Firestore
db = firestore.Client()
urls_ref = db.collection("urls")


def check_api_key(func):
    """
    Decorator function to check the validity of an API key.

    This function is used as a decorator to wrap around other route functions.
    It checks if the 'X-API-Key' header from the request is valid.
    If the API key is valid, the route function is executed.
    If the API key is invalid, an error response is returned.

    Args:
        func (function): The route function to be decorated.

    Returns:
        function: The decorated function.

    """

    @wraps(func)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get("X-API-Key")

        if api_key in valid_api_keys:
            return func(*args, **kwargs)
        error_message = {"error": "Invalid API key"}
        return jsonify(error_message), 401

    return decorated_function


def check_google_safe_browsing(url, google_api_key):
    """
    Checks if a given URL is flagged as a threat by Google Safe Browsing API.

    Args:
        url (str): The URL to be checked.
        google_api_key (str): The API key for accessing Google Safe Browsing API.

    Returns:
        bool: True if the URL is flagged as a threat, False otherwise.
    """
    safe_browsing_url = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find?key="
        f"{google_api_key}"
    )
    payload = {
        "client": {
            "clientId": "thayn-cc",
            "clientVersion": "1.0",
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    safe_browsing_response = requests.post(safe_browsing_url, json=payload, timeout=15)

    return bool(safe_browsing_response.json())


def get_page_title(url):
    """
    Retrieves the title of a web page.

    Args:
        url (str): The URL of the web page.

    Returns:
        str: The title of the web page if found, otherwise "No Title Found".

    Raises:
        requests.exceptions.RequestException: If there is an error reaching the URL.
    """
    try:
        page_response = requests.get(url, timeout=15)
        soup = BeautifulSoup(page_response.text, "html.parser")
        return soup.title.string if soup.title else "No Title Found"
    except requests.exceptions.RequestException:
        return "Error: Unable to reach URL."


def int_to_base(n, base):
    """
    Converts an integer to a list of digits in the specified base.

    Parameters:
    - n (int): The integer to convert.
    - base (int): The base to convert the integer to.

    Returns:
    - list: A list of digits representing the integer in the specified base.
    """
    if n == 0:
        return [0]
    digits = []
    while n:
        digits.append(int(n % base))
        n //= base
    return digits[::-1]


def get_next_emoji_string():
    """
    Generates a new emoji string ID by iterating through all possible combinations of emojis.

    Returns:
        str: The newly generated emoji string ID.
    """
    ids_ref = db.collection("ids")
    random.shuffle(emojis)
    for j in range(1, len(emojis)):
        for sequence in itertools.product(emojis, repeat=j):
            sequence = "".join(sequence)
            doc_refs = ids_ref.where("id", "==", sequence).get()
            if not doc_refs:
                print(f"New ID: {sequence}")
                return sequence


@app.route("/", methods=["GET"])
def index():
    """
    Handles the root route ("/") and returns the index.html file from the "static" directory.

    Returns:
        The index.html file from the "static" directory.
    """
    return send_from_directory("static", "index.html")


@app.route("/privacy", methods=["GET"])
def privacy():
    """
    Redirects the user to the privacy policy page.

    Returns:
        A redirect response to the privacy policy page.
    """
    return redirect("https://github.com/AnalogCyan/" + "thayn.cc/blob/main/PRIVACY.md")


@app.route("/", methods=["POST"])
@check_api_key
def shorten_url():
    """
    Shortens a given URL and returns a shortened URL.

    Returns:
        A dictionary containing the shortened URL.

    Raises:
        ValueError: If the URL is invalid.
    """
    url = request.get_json().get("url")
    scheme = urlparse(url).scheme
    # Validate the URL
    if not validators.url(url):
        return "Invalid URL", 400
    # For security, if a URL doesn't have a scheme, assume it's HTTPS
    if not scheme:
        url = "https://" + url

    # Check if the URL is already in the database
    doc_refs = urls_ref.where("url", "==", url).get()

    # If the URL is already in the database, use the existing id
    if doc_refs:
        url_id = doc_refs[0].to_dict()["id"]
    # If not, generate a new id
    else:
        url_id = get_next_emoji_string()
        owner = valid_api_keys[request.headers.get("X-API-Key")]
        # Add the new id and URL to the database
        urls_ref.add({"id": url_id, "url": url, "owner": owner})

    host_url = request.host_url.replace("http://", "https://")

    return {"short_url": [host_url + id for id in url_id]}, 201


@app.route("/<url_id>")
def redirect_to_url(url_id):
    """
    Redirects to the specified URL based on the given URL ID.

    Args:
        url_id (str): The ID of the URL to redirect to.

    Returns:
        str: The rendered HTML template or an error message if the URL is not found.

    """
    urls = urls_ref.where("id", "==", url_id).stream()
    url = next((url.to_dict()["url"] for url in urls), None)
    if not url:
        return "URL not found", 404
    # return redirect(url)
    title = get_page_title(url)

    if check_google_safe_browsing(url, GOOGLE_API_KEY):
        return render_template("warning.html", url=url, title=title)
    else:
        return render_template("index.html", url=url, title=title)


# Start the Flask application
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
