mysql_hostname=$(ace --skip-initialize-automation-user config database_ace.* | grep '^hostname =' | sed -e 's/^hostname = //')
prefix=""
options="-u ace-superuser --password=$ACE_DB_PASSWORD -h $mysql_hostname"
