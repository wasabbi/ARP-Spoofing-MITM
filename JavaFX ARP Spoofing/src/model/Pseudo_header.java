package model;

public class Pseudo_header {
	public byte[] sourceIP = new byte[4];
	public byte[] destinationIP = new byte[4];
	public byte[] reserved = {0x00};
	public byte[] protocol = {0x06};
	public byte[] tcpLen = new byte[2];
}
