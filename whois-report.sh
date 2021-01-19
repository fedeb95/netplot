if [ -z "$1" ]; then
    echo "Usage: ./whois-report.sh <interface>"
    exit 0
fi
sudo tcpdump -i $1 -w packets.pcap && sudo ./venv/bin/python3 netplot.py -i $1 -r -n -f packets.pcap > addresses.txt
for addr in `cat addresses.txt | xargs`;
    do whois $addr >> report.txt;
done
