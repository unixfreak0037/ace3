# extracts the proxy settings from the config and puts it into the http_proxy and https_proxy env vars
proxy_host=$(ace config -v proxy.host)
proxy_port=$(ace config -v proxy.port)
proxy_user=$(ace config -v proxy.user)
proxy_password=$(ace config -v proxy.password)
proxy_password=$(python -c "import urllib.parse;print (urllib.parse.quote('$proxy_password'))")

http_proxy="http://$proxy_user:$proxy_password@$proxy_host:$proxy_port"
https_proxy="$http_proxy"
