package model;

public class Util {
	public static String bytesToString(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		int i = 0;
		for (byte b : bytes) {
			sb.append(String.format("%02x ", b & 0xff));
			if(++i % 16 == 0) sb.append("\n");
		}
		return sb.toString();
	}
    public static int indexOf(byte[] data, byte[] pattern) {
        int[] failure = computeFailure(pattern);

        int j = 0;

        for (int i = 0; i < data.length; i++) {
            while (j > 0 && pattern[j] != data[i]) {
                j = failure[j - 1];
            }
            if (pattern[j] == data[i]) { 
                j++; 
            }
            if (j == pattern.length) {
                return i - pattern.length + 1;
            }
        }
        return -1;
    }
    static private int[] computeFailure(byte[] pattern) {
        int[] failure = new int[pattern.length];

        int j = 0;
        for (int i = 1; i < pattern.length; i++) {
            while (j>0 && pattern[j] != pattern[i]) {
                j = failure[j - 1];
            }
            if (pattern[j] == pattern[i]) {
                j++;
            }
            failure[i] = j;
        }

        return failure;
    }
	public static short checksum( byte[] message , int length , int offset ) {
		  // Sum consecutive 16-bit words.
		  int sum = 0 ;
		  while( offset < length - 1 ){
		  sum += (int) integralFromBytes( message , offset , 2 );
		  offset += 2 ;
		  } 
		  if( offset == length - 1 ){
		  sum += ( message[offset] >= 0 ? message[offset] : message[offset] ^ 0xffffff00 ) << 8 ;
		  }
		  // Add upper 16 bits to lower 16 bits.
		  sum = ( sum >>> 16 ) + ( sum & 0xffff );
		  // Add carry
		  sum += sum >>> 16 ;
		  // Ones complement and truncate.
		  return (short) ~sum ;
		}
	private static long integralFromBytes( byte[] buffer , int offset , int length ){
		 
		  long answer = 0 ;

		  while( -- length >= 0 ) {
		  answer = answer << 8 ;
		  answer |= buffer[offset] >= 0 ? buffer[offset] : 0xffffff00 ^ buffer[offset] ;
		  ++ offset ;
		  }

		  return answer ;
		}
}
