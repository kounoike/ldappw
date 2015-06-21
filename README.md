# ldappw

LDAPのパスワードを変更するCGI用Pythonアプリ。


## Requirements

* flask
* python-ldap


## Run on Apache

httpd.confに以下の設定を追加

```
ScriptAlias /ldappw "C:\Bitnami\redmine-2.5.0-0\apps\pythonapp\ldappw.cgi"
```

これで、/ldappw/でアクセスできる・・・はず
