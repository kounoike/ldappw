#!python
# coding: utf-8

from flask import Flask, render_template, request, redirect, url_for, session
import ldap
import ldap.modlist
import hashlib
import base64
import os

app = Flask(__name__)
app.debug = True
app.secret_key = "my secret key"

ldap_host = "localhost"
ldap_baseDN = "ou=Person,dc=typemiss,dc=net"
managerDN = "cn=Manager,dc=typemiss,dc=net"


def make_secret(password):
    salt = os.urandom(4)
    h = hashlib.sha1(password)
    h.update(salt)
    return "{SSHA}" + base64.encodestring(h.digest() + salt)


def openldap():
    l = ldap.open(ldap_host)
    l.protocol_version = ldap.VERSION3
    return l


@app.route("/", methods=["POST", "GET"])
def index():
    if request.method == "POST":
        username = request.form.get("username")
        oldpassword = request.form.get("oldpassword")
        newpassword1 = request.form.get("newpassword1")
        newpassword2 = request.form.get("newpassword2")
        dn = request.form.get("dn")

        if newpassword1 == "" or newpassword1 != newpassword2:
            session["err"] = u"パスワードが一致しません"
            return redirect(url_for("index"))

        l = openldap()
        try:
            l.simple_bind_s(dn, oldpassword)
        except ldap.INVALID_CREDENTIALS, e:
            session["err"] = u"旧パスワードが違います"
            return redirect(url_for("index"))
        secret = make_secret(newpassword1)
        l.modify_s(dn, [(ldap.MOD_REPLACE, "userPassword", secret)])

        session["success"] = u"変更しました"
        return redirect(url_for("index"))
    else:
        l = openldap()
        searchScope = ldap.SCOPE_SUBTREE
        result_list = l.search_s(ldap_baseDN, searchScope, "objectClass=inetOrgPerson")
        err = session.get("err")
        success = session.get("success")
        session["err"] = None
        session["success"] = None
        return render_template("index.html", **locals())


@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        newpassword1 = request.form.get("newpassword1")
        newpassword2 = request.form.get("newpassword2")
        dn = request.form.get("dn")
        if newpassword1 == "" or newpassword1 != newpassword2:
            session["err"] = u"パスワードが一致しません"
            return redirect(url_for("admin"))
        l = openldap()
        try:
            l.simple_bind_s(managerDN, request.form.get("adminpassword"))
        except ldap.INVALID_CREDENTIALS, e:
            session["err"] = u"管理者パスワードが違います"
            return redirect(url_for("admin"))
        secret = make_secret(newpassword1)
        l.modify_s(dn, [(ldap.MOD_REPLACE, "userPassword", secret)])

        session["success"] = u"成功しました"
        return redirect(url_for("admin"))
    else:
        l = openldap()
        searchScope = ldap.SCOPE_SUBTREE
        result_list = l.search_s(ldap_baseDN, searchScope, "objectClass=inetOrgPerson")
        success = session.get("success")
        err = session.get("err")
        session["err"] = None
        session["success"] = None
        return render_template("admin.html", **locals())


@app.route("/admin_adduser", methods=["GET", "POST"])
def admin_adduser():
    if request.method == "POST":
        newpassword1 = request.form.get("newpassword1")
        newpassword2 = request.form.get("newpassword2")
        uid = request.form.get("username")
        sn = request.form.get("sn")
        givenName = request.form.get("givenName")
        displayName = "{0} {1}".format(sn, givenName)
        mail = request.form.get("email")
        dn = "uid={0},{1}".format(uid, ldap_baseDN)
        if newpassword1 == "" or newpassword1 != newpassword2:
            session["err"] = u"パスワードが一致しません"
            return redirect(url_for("admin_adduser"))
        l = openldap()
        try:
            l.simple_bind_s(managerDN, request.form.get("adminpassword"))
        except ldap.INVALID_CREDENTIALS, e:
            session["err"] = u"管理者パスワードが違います"
            return redirect(url_for("admin_adduser"))
        secret = make_secret(newpassword1)
        attrs = {
            "uid": str(uid),
            "objectClass": "top",
            "objectClass": "inetOrgPerson",
            "cn": str(uid),
            "sn": str(sn),
            "givenName": str(givenName),
            "displayName": str(displayName),
            "mail": str(mail),
            "userPassword": secret
        }
        try:
            l.add_s(dn, ldap.modlist.addModlist(attrs))
        except ldap.LDAPError, e:
            session["err"] = u"LDAPエラーが発生しました:{0}".format(e)
            return redirect(url_for("admin_adduser"))

        session["success"] = u"成功しました"
        return redirect(url_for("admin_adduser"))
    else:
        success = session.get("success")
        err = session.get("err")
        session["err"] = None
        session["success"] = None
        return render_template("admin_adduser.html", **locals())


if __name__ == "__main__":
    port = 5100
    app.run(port=port)
