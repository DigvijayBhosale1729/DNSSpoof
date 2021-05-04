apt install python3-pip git libnfnetlink-dev libnetfilter-queue-dev
echo "[+] netfilterqueue dependancies installed"
pip3 install -U git+https://github.com/kti/python-netfilterqueue
echo "[+] netfilterqueue installed"
pip3 install scapy
echo "[+] scapy installed"
