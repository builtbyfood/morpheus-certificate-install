appliance_url 'https://x'

# >>> morpheus-certificate-install managed block (do not edit by hand) >>>
# written 20261105-120000 — previous values (if any) are commented above
nginx['ssl_certificate'] = '/etc/morpheus/ssl/m_cust_test.crt'
nginx['ssl_server_key'] = '/etc/morpheus/ssl/m_cust_test.key'
# <<< morpheus-certificate-install managed block <<<
