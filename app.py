import itertools
import os
from functools import wraps
import random
from urllib.parse import urlparse

import emoji
import google.cloud.firestore as firestore
import requests
import validators
from bs4 import BeautifulSoup
from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
)
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from google.cloud.firestore import Increment
from google.cloud import secretmanager


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
project_id = "358507212056"
name = f"projects/{project_id}/secrets/google_safe_browsing/versions/latest"
GOOGLE_API_KEY = client.access_secret_version(
    request={"name": name}
).payload.data.decode("UTF-8")

# Define a dictionary of valid API keys
client = secretmanager.SecretManagerServiceClient()
project_id = "358507212056"
secrets = ["Cyan", "Meghan"]
valid_api_keys = {}
for secret_id in secrets:
    name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"
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
    ":100:",
    ":anger_symbol:",
    ":collision:",
    ":dizzy:",
    ":sweat_droplets:",
    ":dashing_away:",
    ":hole:",
    ":bomb:",
    ":speech_balloon:",
    ":eye_in_speech_balloon:",
    ":left_speech_bubble:",
    ":right_anger_bubble:",
    ":thought_balloon:",
    ":zzz:",
]
for i in range(len(emojis)):
    emojis[i] = emoji.emojize(emojis[i])

# Initialize Firestore
db = firestore.Client()
urls_ref = db.collection("urls")


# Function to require a valid API key
def check_api_key(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        # Access the 'X-API-Key' header from the request
        api_key = request.headers.get("X-API-Key")

        # Check if the API key is valid
        if api_key in valid_api_keys:
            # API key is valid, proceed with the route function
            return func(*args, **kwargs)
        else:
            # API key is invalid, return error response
            error_message = {"error": "Invalid API key"}
            return jsonify(error_message), 401

    return decorated_function


# Function to check if a URL is safe using Google Safe Browsing
def check_google_safe_browsing(url, google_api_key):
    safe_browsing_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={google_api_key}"
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
    response = requests.post(safe_browsing_url, json=payload)

    if response.json():
        return True
    else:
        return False


# Function to get the title of a webpage
def get_page_title(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")
        return soup.title.string if soup.title else "No Title Found"
    except requests.exceptions.RequestException as e:
        return "Error: Unable to reach URL."


def int_to_base(n, base):
    if n == 0:
        return [0]
    digits = []
    while n:
        digits.append(int(n % base))
        n //= base
    return digits[::-1]


def get_next_emoji_string():
    ids_ref = db.collection("ids")
    random.shuffle(emojis)
    for i in range(1, len(emojis)):
        for sequence in itertools.product(emojis, repeat=i):
            sequence = "".join(sequence)
            doc_refs = ids_ref.where("id", "==", sequence).get()
            if not doc_refs:
                print(f"New ID: {sequence}")
                return sequence


# Route for landing page
@app.route("/", methods=["GET"])
def index():
    return send_from_directory("static", "index.html")


# Route for privacy policy
@app.route("/privacy", methods=["GET"])
def privacy():
    return redirect("https://github.com/AnalogCyan/thayn.cc/blob/main/PRIVACY.md")


# Route for generating a new shortened URL
@app.route("/", methods=["POST"])
@check_api_key
def shorten_url():
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


# Route for routing the shortened URL
@app.route("/<url_id>")
def redirect_to_url(url_id):
    urls = urls_ref.where("id", "==", url_id).stream()
    url = next((url.to_dict()["url"] for url in urls), None)
    if not url:
        return "URL not found", 404
    else:
        scheme = urlparse(url).scheme
        if scheme != "https":
            url = url.replace(scheme, "https")
    # return redirect(url)
    title = get_page_title(url)

    if check_google_safe_browsing(url, GOOGLE_API_KEY):
        return render_template("warning.html", url=url, title=title)
    else:
        return render_template("index.html", url=url, title=title)


# Start the Flask application
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
