#Step 1: Imports
from scapy.all import *
from prettytable import PrettyTable
from collections import Counter
import plotly.express as px

packets=rdpcap("wireshark.pcap")
#Step 2: Read and Append
srcIP=[]
for pkt in packets:
    if IP in pkt:
        try:
            srcIP.append(pkt[IP].src)
        except:
            pass

#Step 3: Count
cnt=Counter()
for ip in srcIP:
   cnt[ip] += 1

#Step 4: Table and Print
table= PrettyTable(["IP", "Count"])
for ip, count in cnt.most_common():
   table.add_row([ip, count])
print(table)
 

#Step 4: Add Lists
xData=[]
yData=[]

for ip, count in cnt.most_common():
  xData.append(ip)
  yData.append(count)

packets.summary()

#Step 5: Plot
fig = px.bar(yData, x=xData, y=yData)

fig.update_layout(
    title="PCAP ANALYSIS",
    xaxis_title="DESTINATION IP ADDRESS",
    yaxis_title="PACKET COUNT",
       font=dict(
        family="Cambria",
        size=16,
        color="black"
    )
)

fig.show()





