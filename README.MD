## Загружаем пользователей из Active Directory в БД
Простая синхронизация таблицы БД через LDAP с Active Directory

Для работы потребуется internal пакет config, пример реализации: 
```
package config

const (
	Host      = "ldap://dc.local:389"
	User      = "dc_admin@dc.local"
	Pass      = "PassWord"
	MysqlHost = "user:pass@tcp(mysql-db.ru:3306)/database?parseTime=true"
)
```