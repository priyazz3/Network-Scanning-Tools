strings wireshark.pcap >> output1.pcap
echo "[+] parsing the PCAP file"
grep -i start output1.pcap | uniq >> transmitted.b64
sed -i -e 's/\$\$START\$\$//g' transmitted.b64
echo "[+] cleaning PCAP file"
rm output1.pcap
echo "[+] transmitted.b64 created"
base64 -d transmitted.b64 > finaloutput.txt
echo "[+] finaloutput.txt created"