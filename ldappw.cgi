#!python

from wsgiref.handlers import CGIHandler
from app import app
import mimetypes

mimetypes.add_type("application/x-font-woff", ".woff")
mimetypes.add_type("application/font-woff2", ".woff2")
mimetypes.add_type("application/x-font-otf", ".otf")
mimetypes.add_type("application/octet-stream", ".ttf")
mimetypes.add_type("application/vnd.ms-fontobject", ".eot")

CGIHandler().run(app)
