package model;

import java.util.Arrays;

public class ARP {
	private byte[] destinationMAC = new byte[6];
	private byte[] sourceMAC = new byte[6];
	private byte[] ethernetType = {0x08,0x06}; //ARP
	private byte[] hardwareType = {0x00,0x01}; //Ethernet
	private byte[] protocolType = {0x08,0x00}; //IPv4
	private byte hardwareSize = 0x06; //MAC Size
	private byte protocolSize = 0x04; //IP Size
	private byte[] opcode = new byte[2]; //0x0001, request; 0x0002, reply
	private byte[] senderMAC = new byte[6];
	private byte[] senderIP =  new byte[4];
	private byte[] targetMAC = new byte[6];
	private byte[] targetIP =  new byte[4]; 
	//ARP Request를 보낼 때, targetIP는 MAC 주소를 알아내려는 기기다.
	//targetIP만 알고 있고 targetMAC은 모르기에
	//targetMAC은 00:00:.....이고 targetIP만 적혀있다.
	//ARP Reply를 보낼 때, targetIP는 자신에게 MAC주소를 물은 게이트웨이다.
	//그러기에 senderIP, senderMAC은 차례로 자신의 IP, 게이트웨이가 물은 자신의 MAC이다.
	
	public void makeARPRequest(byte[] sourceMAC, byte[] senderIP, byte[] targetIP) {
		//IP를 알고 있어서 MAC을 알아낼 때
		Arrays.fill(destinationMAC, (byte)0xff); //Broadcast
		System.arraycopy(sourceMAC, 0, this.sourceMAC, 0, 6);
		opcode[0] = 0x00; opcode[1] = 0x01; //request
		System.arraycopy(sourceMAC, 0, this.senderMAC, 0, 6); //ARP request 같은 경우, sourceMAC과 senderMAC이 다 게이트웨이 본인이 되어야한다.
		System.arraycopy(senderIP, 0, this.senderIP, 0, 4);
		Arrays.fill(targetMAC, (byte) 0x00); //Broadcast 상대방 MAC을 모른다는 의미로 0x00을 채워준다.
		System.arraycopy(targetIP, 0, this.targetIP, 0, 4);
	}
	
	public void makeARPReply(byte[] destinationMAC, byte[] sourceMAC, byte[] senderMAC,
			byte[] senderIP, byte[] targetMAC, byte[] targetIP) {
		//destMAC에게, sourceMAC이
		System.arraycopy(destinationMAC, 0, this.destinationMAC, 0, 6);
		System.arraycopy(sourceMAC, 0, this.sourceMAC, 0, 6);	//ARP reply 는 sourceMAC이랑 senderMAC이 다를 수 있다?
		opcode[0] = 0x00; opcode[1] = 0x02; //reply
		System.arraycopy(senderMAC, 0, this.senderMAC, 0, 6);
		System.arraycopy(senderIP, 0, this.senderIP, 0, 4);
		System.arraycopy(targetMAC, 0, this.targetMAC, 0, 6);
		System.arraycopy(targetIP, 0, this.targetIP, 0, 4);
	}
	
	public byte[] getPacket() {
		byte[] bytes = new byte[42]; //ARP는 42바이트다.
		System.arraycopy(destinationMAC, 0,  bytes, 0, destinationMAC.length);
		System.arraycopy(sourceMAC, 0,  bytes, 6, sourceMAC.length);
		System.arraycopy(ethernetType, 0,  bytes, 12, ethernetType.length);
		System.arraycopy(hardwareType, 0,  bytes, 14, hardwareType.length);
		System.arraycopy(protocolType, 0,  bytes, 16, protocolType.length);
		bytes[18] = hardwareSize;
		bytes[19] = protocolSize;
		System.arraycopy(opcode, 0,  bytes, 20, opcode.length);
		System.arraycopy(senderMAC, 0,  bytes, 22, senderMAC.length);
		System.arraycopy(senderIP, 0,  bytes, 28, senderIP.length);
		System.arraycopy(targetMAC, 0,  bytes, 32, targetMAC.length);
		System.arraycopy(targetIP, 0,  bytes, 38, targetIP.length);
		
		return bytes;
	}
}
