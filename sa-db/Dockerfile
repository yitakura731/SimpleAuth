FROM mariadb/server

# セットアップ用スクリプトを配置
COPY ./setup/init.sql /docker-entrypoint-initdb.d/

# 文字コードをUTF8に設定
COPY ./charset.cnf /etc/mysql/mariadb.conf.d/
