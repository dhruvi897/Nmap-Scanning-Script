import nmap
import csv
scanner = nmap.PortScanner()

print("Target Scanning using Nmap")
print("<----------------------------------------------------->")

ip_addr = input("Enter target IP address: ")
print("The IP you entered is: ", ip_addr)
type(ip_addr)
print("Starting..")
print("Nmap Version: ", scanner.nmap_version())
scanner.scan(ip_addr, '1-65535', '-v -sS -sV -sC -A -O')
print(scanner.scaninfo())
print("Ip Status: ", scanner[ip_addr].state())
print(scanner[ip_addr].all_protocols())
print("Open Ports: ", scanner[ip_addr]['tcp'].keys())

output=scanner.csv()
        	
l=list(output.split("\n"))

for i in range(len(l)):
	l[i]=l[i].split(";")

with open('output_nmap.csv','w') as f:
	writer=csv.writer(f)
	writer.writerows(l)

print("Check the output file, output_nmap.csv, for detailed scan results!")
