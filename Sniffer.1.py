
import socket
import struct
import time
import dns.resolver
import sys
from multiprocessing import Process, Lock, Value


import threading
#sends dns get ip
class sender_dns:

	def send(self,domain):

		ips=[]
		myResolver = dns.resolver.Resolver()

		try:

			myAnswers = myResolver.query(domain, "A")  # A record that points to the IP address of the domain
			print ("answers: ", myAnswers) #answers in bytes
			for rdata in myAnswers:

				print ("RDATA_IP: "+str(rdata))
				ips.append(str(rdata))
		except:
			print ("Query failed")

		myResolver.nameservers = ['8.8.8.8']

		try:

			myAnswers = myResolver.query(domain, "A")  # A record that points to the IP address of the domain
			print ("answers: ", myAnswers)
			for rdata in myAnswers:

				print ("RDATA_IP: "+str(rdata))
				ips.append(str(rdata))
		except:
			print ("Query failed")

		myResolver.nameservers = ['8.8.4.4']
		try:

			myAnswers = myResolver.query(domain, "A")
			#print ("answers: ", myAnswers)
			for rdata in myAnswers:

				print ("RDATA_IP"+str(rdata))
				ips.append(str(rdata))
		except:
			print ("Query failed")


		return ips


class Packet:

	dest_mac=""
	source_mac=""
	eth_proto=""
	version=""
	header_length=""
	ttl=""
	protocol=""  #17-UDP  6-TCP  1-ICMP
	source_ip=""
	dest_ip=""
	source_port=""
	dest_port=""
	seq=""
	ack=""
	data=""
	domain=""
	is_dns=""
	def set_dest_mac(_dest_mac):
		dest_mac=_dest_mac




class Sniffer:


	#returns the ip of the computer
	def get_my_ip(self):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.connect(("8.8.8.8", 80))
		my_ip=str(s.getsockname()[0])
		s.close()
		return my_ip

	#gets the mac addresses and protocol
	#ethernet frame: RECIVER - 6 bytes, SENDER-6 bytes, TYPE (0x800-ipv4,0x806 ARP REQ/RES, 0x86DD=IPV6) -2 bytes,PAYLOAD(IP/ARP frame+padding)- 46-1500 bytes- DATA WE WANT

	def ethernet_frame(self,data):


		dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14]) # 6 bytes *2 for mac is H=2 bytes
		return self.get_mac_addr(dest_mac), self.get_mac_addr(src_mac), socket.htons(proto), data[14:]
	#return properly looking mac address by separating to 2 chunks and joining them together in big letters: (AA:BB:CC:DD:EE:FF)
	def get_mac_addr(self,bytes_addr):
		bytes_str = map('{:02x}'.format, bytes_addr)
		return ':'.join(bytes_str).upper()

	# unpacks the header of the data, version_header_len is 1 byte so we will have to seperate it to version and header length
	def ipv4_packet(self,data):
		version_header_length = data[0]
		version = version_header_length >> 4  # shifting the bits by four to get only version
		header_length = (version_header_length & 15) * 4  # whole header size
		ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[ :20])  # the format to get ttl.., 20 bytes is header size without  ip option
		return version, header_length, ttl, proto, self.ipv4_format(src), self.ipv4_format(target), data[header_length:]

	# returning what we have found and the payload

	# returns a  properly formated ip address with dots between numbers in a string!
	# 127, 0 ,0 ,1 => "127.0.0.1"
	def ipv4_format(self,addr):
		return '.'.join(map(str, addr))

	# unpacks ICMP packet reuturn the packet's info and the payload-(data[4:])
	# PROTOCOL 1
	def icmp_packet(self,data):
		icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
		return icmp_type, code, checksum, data[4:]

	# PROTOCOL 6
	# unpacks TCP packets
	def tcp_segment(self,data):
		(src_port, dest_port, seq, ack, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
		offset = (
							 offset_reserved_flags >> 12) * 4  # shifting 12 bits *4 =12 bytes to the right so we'll have only offset which is 4 bytes

		flag_urg = (offset_reserved_flags & 32) >> 5  # 32 is 100000 so we zero everything except the first byte
		flag_ack = (offset_reserved_flags & 16) >> 4
		flag_psh = (offset_reserved_flags & 8) >> 3
		flag_rst = (offset_reserved_flags & 4) >> 2
		flag_syn = (offset_reserved_flags & 2) >> 1
		flag_fin = (offset_reserved_flags & 1)

		return src_port, dest_port, seq, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

	# def domainBuilder(DnsData):



	# PROTOCOL 17
	# unpacks UDP packets
	def udp_segment(self,data, dest):
		is_dns = False


		src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
		if (src_port == 53 and dest==self.get_my_ip()):  # THE PACEKT WHEN THE COMPUTER GETS THE DNS REQUEST FROM THE ROUTER THATS WHEN WE WANT TO SEND THE MEESAGE
			is_dns = True
			print("DEST= "+dest+"  MY_IP= "+self.get_my_ip())



		return src_port, dest_port, size, data[8:], is_dns

	def sniff(self):

		p = Packet()


		conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) #ntohs good bytes order and compatible with all machines

		raw_data, addr = conn.recvfrom(65536)
		dest_mac, src_mac, eth_proto, data = self.ethernet_frame(raw_data)
		print('\nETHERNET_FRAME:')
		print('		Dest:{}, Source: {},Ethernet Protocol: {}'.format(dest_mac, src_mac, eth_proto))

		p.dest_mac=dest_mac
		p.source_mac=src_mac
		p.eth_proto=eth_proto

			# checks for ipv4
		if eth_proto == 8:
			(version, header_length, ttl, proto, src, target, data) = self.ipv4_packet(data)
			print('	IPV4_PACKET:')
			print('		Version: {}, Header length: {}, TTL: {}'.format(version, header_length, ttl))
			print('		Protocol: {}, Source: {}, Destantion: {}'.format(proto, src, target))



			p.version=version
			p.header_length=header_length
			p.ttl=ttl

			p.protocol=proto
			p.source_ip=src
			p.dest_ip=target
			p.data=data

			if (dest_mac == "FF:FF:FF:FF:FF:FF" or src_mac == "FF:FF:FF:FF:FF:FF"):
				print (
					"\n--------------------------------------------ARP--------------------------------------------")

			if (proto == 6):
				src_port, dest_port, seq, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data=self.tcp_segment(data)
				print(' TCP ')
				print('		Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
				print(' 	SEQ: {}, ACK: {}'.format(seq, ack))
				print(' 	FLAGS:')
				print(
						'			flag_urg: {} ,flag_ack: {}, flag_psh: {}, flag_rst: {}, flag_syn: {}, flag_fin: {}'.format(
							flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
				print("""	DATA: \n	{}""".format(data))

				p.source_port=src_port
				p.dest_port=dest_port
				p.seq=seq
				p.ack=ack
					#I DONT THINK SENDING FLAGS IS NECESSARY BUT I COULD ADD THEM TOO




			#UDP
			elif (proto == 17):
				p.src_port, p.dest_port, size, data, p.is_dns = self.udp_segment(data, target)

				print(' UDP ')
				print('		Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
				print('		SIZE: {}'.format(size))

				if (dns):
					print ("-------DNS-------")
					print("""	DATA: \n	{}""".format(data))







			elif (proto == 1):
				icmp_type, code, checksum, data = self.icmp_packet(data)  # getting from the function the info
				p.protocol==1

				print('	ICMP ')
				print('		Icmp_type: {}, Code: {}, checksum: {},'.format(icmp_type, code, checksum))
				print("""	DATA: \n	{}""".format(data))

		return p




#building domain from bytes
def domain_builder( data):
	# thats where the domain_data starts after 20 bytes


	counter = 20
	neto_size_string = '0'

	size_counter = 1;
	is_size = False
	domain = ''



	print("DaTa:{}".format(data))
	while (size_counter != 0):

		size_counter = size_counter - 1
		next_string_size_byte = int.from_bytes( data[counter:(counter + 1)], byteorder=sys.byteorder)

		next_string_size = str(next_string_size_byte)

		# taking all numbers from a byte the numbers represent the size of the string after them



		for num in next_string_size:

			if (num.isdigit()):

				neto_size_string = neto_size_string + num
				is_size = True





		if(is_size):
			is_size = False
			size_counter = int(neto_size_string)



			if (size_counter == 0): #at the end of a dns format the size is zero
				break



		print("DATA FOR DOMAIN: "+str(data[counter+1:(counter+2)]))

		domain = domain + str(struct.unpack('! 1s', data[counter + 1:(counter + 2)]))[3]

		counter = counter + 1
		neto_size_string = '0'

	return domain,counter

class ip_getter:

	ips_list=[]
	def ip_get(self,counter, data):



		print("Counter is now in: counter: ",counter)
		print("data segment: ",data[counter:counter+10])

		index=data[counter: ].find(b'\x00\x04')#finding the size byte before the ip


		if index!=-1:

			index=index+counter #index inside data not inside the data cut that's why we do counter+
			print("index: " + str(index))
			print("data index: ", data[index:index + 10])

			ip_byte=data[index+2: index+6] #2 bytes after index to skip on data length 6 bytes after because 4 bytes are the the ip
			ip=""

			for byte in ip_byte:# apparently looping bytes convert them to dec, LUCKY!
				ip=ip+str(byte)
				ip=ip+"."
			ip=ip[ :-1]
			self.ips_list.append(ip)
			#print("IP: " +ip)

			self.ip_get(index+6,data)#searching for more ips inside the data starting 6 bytes after the index to pass the size of the message-2 bytes and the ip-4 bytes


def compare_ips(domain, ips_from_packet):
	s=sender_dns()
	print("DOMAIN: "+domain)
	ips_from_servers=s.send(domain)
	print("IPS_FROM_SERVERS: "+str(ips_from_servers))

	for ip_server in ips_from_servers:
		for ip_packet in ips_from_packet:
			if ip_server==ip_packet:
				return "___________THIS SITE IS SAFE!____________"
	return "________	SOMETHING IS WRONG THIS SITE MAY NOT BE THE REAL SITE_____________"

def spoof():
	# it will refresh every 20 seconds
	s = Spoofer(20)
	s.startSpoofing()

def sniffer():

	s = Sniffer()
	ip_get_var = ip_getter()
	while (True):

		packet = s.sniff()

		if packet.protocol == 17:
		#	lock.acquire()  ###########################
			if (packet.is_dns):


				domain, counter = domain_builder(packet.data)
				domain = domain[:-1]
				domain = domain.replace("\\", ".")

				print("SRC: " + packet.source_ip, "DEST: " + packet.dest_ip, "DOMAIN: " + domain)
				ip_get_var.ip_get(counter, packet.data)
				print("FOUND THESE IPS: " + str(ip_get_var.ips_list))

				print(str(compare_ips(domain, ip_get_var.ips_list)))
				ip_get_var.ips_list = []  # reseting the ips list for a new domain got to keep things clean

		#	lock.release()  #############################
			#else:
			#	print("SRC: " + packet.source_ip,
			#		  "DEST: " + packet.dest_ip + " REGULAR UDP PACKET" + "\nseq= " + str(packet.seq) + " ack= " + str(packet.ack))

		else:
			print("SRC: " + packet.source_ip, "DEST: " + packet.dest_ip, " PROTOCOL: "+ str(packet.protocol)	)


def main():


	#lock= Lock()###################
	#spoof_thread = threading.Thread(target=spoof)
	#spoof_thread.start()

	sniff_thread = threading.Thread(target=sniffer)
	sniff_thread.start()
	#sniffer()

main()
