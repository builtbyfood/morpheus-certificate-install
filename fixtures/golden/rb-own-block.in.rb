appliance_url 'https://198.51.100.20'
elasticsearch['es_hosts'] = {'127.0.0.1' => 9200}

# >>> morpheus-certificate-install managed block (do not edit by hand) >>>
# written 20260101-000000 — previous values (if any) are commented above
nginx['ssl_certificate'] = '/etc/morpheus/ssl/a_test.crt'
nginx['ssl_server_key'] = '/etc/morpheus/ssl/a_test.key'
# <<< morpheus-certificate-install managed block <<<
