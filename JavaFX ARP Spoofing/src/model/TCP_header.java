package model;

public class TCP_header {
	public byte[] sourcePort = new byte[2];
	public byte[] destinationPort = new byte[2];
	public byte[] sequence = new byte[4];
	public byte[] ackSeq = new byte[4];
	public byte[] dataOffsetAndReserv = {0x50};
//	public byte[] flag_res = new byte[3];
//	public byte[] flag_non = new byte[1];
	public byte[] flag = new byte[1];
//	public byte[] flag_con = new byte[1];
//	public byte[] flag_ecn = new byte[1];
//	public byte[] flag_urg = new byte[1];
//	public byte[] flag_ack = new byte[1];
//	public byte[] flag_psh = new byte[1];
//	public byte[] flag_rst = new byte[1];
//	public byte[] flag_syn = new byte[1];
//	public byte[] flag_fin = new byte[1];
	public byte[] windowSize = new byte[2];
	public byte[] checksum = {0x00, 0x00};
	public byte[] urgentPtr = {0x00, 0x00};
}
