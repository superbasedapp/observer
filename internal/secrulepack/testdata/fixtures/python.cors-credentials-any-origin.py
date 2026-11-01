from flask import Flask
from flask_cors import CORS
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = Flask(__name__)
# ruleid: python.cors-credentials-any-origin
CORS(app, supports_credentials=True)
# ruleid: python.cors-credentials-any-origin
CORS(app, origins="*", supports_credentials=True)
# ok: python.cors-credentials-any-origin
CORS(app, origins=["https://app.example.com"], supports_credentials=True)
# ok: python.cors-credentials-any-origin
CORS(app)

api = FastAPI()
# ruleid: python.cors-credentials-any-origin
api.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"])
# ok: python.cors-credentials-any-origin
api.add_middleware(CORSMiddleware, allow_origins=["https://app.example.com"], allow_credentials=True)
# ok: python.cors-credentials-any-origin
api.add_middleware(CORSMiddleware, allow_origins=["*"])

CORS_ALLOW_CREDENTIALS = True
# ruleid: python.cors-credentials-any-origin
CORS_ALLOW_ALL_ORIGINS = True
