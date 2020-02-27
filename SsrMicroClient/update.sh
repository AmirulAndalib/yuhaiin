wget https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/apple.china.conf -O apple.china.conf
wget https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/google.china.china.conf -O google.china.china.conf
wget https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf -O accelerated-domains.china.conf
cat custom.conf | sed 's/$/ direct/g' > SsrMicroClient.conf
cat accelerated-domains.china.conf | sed 's/server=\///g' | sed 's/\/114\.114\.114\.114/ direct/g' >> SsrMicroClient.conf
cat google.china.china.conf | sed 's/server=\///g' | sed 's/\/114\.114\.114\.114/ direct/g' >> SsrMicroClient.conf
cat apple.china.conf | sed 's/server=\///g' | sed 's/\/114\.114\.114\.114/ direct/g' >> SsrMicroClient.conf
cat ../cn/cn.acl | sed 's/$/ direct/g' >> SsrMicroClient.conf
rm apple.china.conf google.china.china.conf accelerated-domains.china.conf
