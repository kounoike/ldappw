#!python
# coding: utf-8

from flask import Flask, render_template, request, redirect, url_for
import ldap
import hashlib
import base64
import os

app = Flask(__name__)
app.debug = True

ldap_host = "localhost"
ldap_baseDN = "dc=typemiss,dc=net"


def make_secret(password):
    salt = os.urandom(4)
    h = hashlib.sha1(password)
    h.update(salt)
    return "{SSHA}" + base64.encodestring(h.digest() + salt)


def error(message):
    return render_template("error.html", message=message)


def success():
    return render_template("success.html")


@app.route("/", methods=["POST", "GET"])
def index():
    if request.method == "POST":
        username = request.form.get("username")
        oldpassword = request.form.get("oldpassword")
        newpassword1 = request.form.get("newpassword1")
        newpassword2 = request.form.get("newpassword2")

        if newpassword1 == "" or newpassword1 != newpassword2:
            return error(u"パスワードが一致しません")

        l = ldap.open(ldap_host)
        l.protocol_version = ldap.VERSION3
        searchScope = ldap.SCOPE_SUBTREE
        retrieveAttributes = ["mail", "dn"]
        result_list = l.search_s(ldap_baseDN, searchScope, "uid=%s" % username)
        if len(result_list) == 0:
            return error(u"ユーザ名が見つかりません")
        dn = result_list[0][0]
        print dn
        try:
            l.simple_bind_s(dn, oldpassword)
        except ldap.INVALID_CREDENTIALS, e:
            return error(u"旧パスワードが違います")
        secret = make_secret(newpassword1)
        print secret
        l.modify_s(dn, [(ldap.MOD_REPLACE, "userPassword", secret)])

        return success()
    else:
        return render_template("index.html")

if __name__ == "__main__":
    port = 5100
    app.run(port=port)
