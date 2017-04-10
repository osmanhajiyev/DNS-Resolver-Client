
import java.net.InetAddress;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.util.*;
//java.util.LinkedList<E>


// Lots of the action associated with handling a DNS query is processing 
// the response. Although not required you might find the following skeleton of
// a DNSreponse helpful. The class below has bunch of instance data that typically needs to be 
// parsed from the response. If you decide to use this class keep in mind that it is just a 
// suggestion and feel free to add or delete methods to better suit your implementation as 
// well as instance variables.



public class DNSResponse {
	private int queryID;                  // this is for the response it must match the one in the request 
    private int answerCount = 0;          // number of answers  
    private boolean decoded = false;      // Was this response successfully decoded
    private int nsCount = 0;              // number of nscount response records
    private int additionalCount = 0;      // number of additional -alternate- response records
    private boolean authoritative = false;// Is this an authoritative record
    //NEW
    private boolean is_resp = false;			  // Is this really a query response
    private int rc = 0;
    private boolean tracingOn = false;
    private boolean finished;
    private String ip;
    private String cname1 = "";
    private String original_fqdn = "";
    // Note you will almost certainly need some additional instance variables.

    // When in trace mode you probably want to dump out all the relevant information in a response


    // Did we find an Answer?
    boolean finished(){
    	return finished;
    }

    // Set the cname
    String cname(){
    	return cname1;
    }

    // Get type of data
    String getType(int type0){
    	switch (type0){
    		case 1:
    			return "A";
    		case 2:
   				return "NS";
			case 5:
 				return "CN";
    		case 28:
    			return "AAAA";
    		default:
    			return Integer.toString(type0);
    	}
    }

    // Get the name of the next server to query
	String getNextServer(){
		return ip;
	}

	// 
	String parseType2(DataInputStream stream) throws IOException {
		ArrayList<String> al = new ArrayList<String>();
		boolean compress = false;
		int posi = -1;
		int i = stream.readUnsignedByte();
		try{
			while (i != 0){
				if (i == 0xc0){

					// x number of bytes to skip after resetting back to beginning
					int x = stream.readUnsignedByte();
					compress = true;
					if(posi == -1){
						posi = stream.available();
					}
					stream.reset();
					stream.mark(stream.available());
					stream.skipBytes(x);
					i = stream.readUnsignedByte();
				} else {
					byte[] ba;
					ba = new byte[i];
					for(int j = 0; j < i; j++){
						ba[j] = stream.readByte();
					} 
					al.add(new String(ba));
					i = stream.readUnsignedByte();
				}
			}
			String addr = "";		
			for (int l = 0; l < al.size(); l++){
				addr = addr + al.get(l) + ".";
			}		
			
			if (compress){
				int avail = stream.available();

				// Skippy = bytes we have to skip that we got next to from compressed byte
				int skippy = avail - posi;
				stream.skip(skippy);
			}
			return addr.substring(0, addr.length()-1);

	    } finally {
      		//stream.close();
  		}
	}


	String parseType1(DataInputStream stream, int dataLengt) throws IOException {
		int[] ints = new int[dataLengt];
		try{
			for(int k = 0; k < dataLengt; k++){
				ints[k] = stream.readUnsignedByte();
			}
			String addr = "";	
			for (int m = 0; m < dataLengt; m++){
			addr = addr + ints[m] + ".";	
			}
			
			return addr.substring(0, addr.length()-1);

	    } finally {
      		//stream.close();
  		}
	}

	String parseType28(DataInputStream stream, int dataLengt) throws IOException {
		int[] ints = new int[dataLengt/2];
		try{
			for(int k = 0; k < dataLengt/2; k++){
				ints[k] = stream.readUnsignedShort();
			}
			String addr = "";	
			for (int m = 0; m < dataLengt/2; m++){
			addr = addr + Integer.toHexString(ints[m]) + ":";	
			}
			
			return addr.substring(0, addr.length()-1);

	    } finally {
      		//stream.close();
  		}
	}



	// CONSTRUCTOR for DNSResponse
	public DNSResponse (byte[] data, int len, boolean tracing, String original_fqdn) 
	throws IOException {

		this.original_fqdn = original_fqdn;
		tracingOn = tracing;
    	DataInputStream dataStr = new DataInputStream(new ByteArrayInputStream(data));
    	try {
	    	// The following are probably some of the things 
		    // you will need to do.
    		finished = false;
		 	dataStr.mark(256); //???????????????????????????????????????????????
			// 0-15: Query ID
			queryID = dataStr.readUnsignedShort();
		
			// 0: QR | 1-4: Opcode | 5: AA | 6: TC | 7: RD |
			byte model = (byte)0b10000100;
			byte test = dataStr.readByte();
			byte result = (byte)(model & test);
			
			// Determine from bits what type of result we have, authoritative or not
			switch(result){
				case (byte)0b10000000:	is_resp = true;
										authoritative = false;
										break;
				case (byte)0b10000100:	is_resp = true;
										authoritative = true;
										break;
				default:				authoritative = false;
										break;
			}

			// Trace
			if(tracingOn){
				System.out.println("Response ID: " + queryID + " Authoritative = " + authoritative);
			}

			// 0: RA | 1-3: Z | 4-7: RCODE
			byte model2 = (byte)0b00000111;
			byte test2 = dataStr.readByte();
			byte result2 = (byte)(model2 & test2);

			// Determine the type of error from the bits
			switch(result2){
				case (byte)0b00000000:	rc = 0;		// No Error
										break;
				case (byte)0b00000001:	rc = 1;		// This is used when the name server explicitly reports a value of 3 in the RCODE of the header.
										break;
				case (byte)0b00000010:	rc = 2;		// The lookup times out.
										break;
				case (byte)0b00000011:	rc = 3;		// Too many queries are attempted without resolving the address.
										break;
				case (byte)0b00000100:	rc = 4;		// Any other errors that result in an address not being resolved. Examples would include things like getting a 5 back in the RCODE.
										break;
				case (byte)0b00000101:	rc = 5;		// Refused
										break;
				default:				//uh-oh		// Shouldn't ever happen
										break;
			}


			if(rc == 1){
				System.out.println(original_fqdn + " -1	A 0.0.0.0");
			} else if (rc == 4){
				System.out.println(original_fqdn + " -4	A 0.0.0.0");
			} else {

				// 0-15: QD Count
				dataStr.skipBytes(2);

				// 0-15: AN Count
				answerCount = dataStr.readUnsignedShort();

				// 0-15: NS Count
				nsCount = dataStr.readUnsignedShort();

				// 0-15: AR Count
				additionalCount = dataStr.readUnsignedShort();

				// Queries =============================================

				int skip = -1;
				while(skip != 0){				//skips query name
					skip = dataStr.readByte();
					dataStr.skipBytes(skip);
				}
				dataStr.skipBytes(4); 			//skips class and type

				int fore = answerCount + nsCount + additionalCount;

				String name;
				int type;
	    		int class1;
	    		int ttl;
	    		int dataLength;
	    		String data1;
	    		ArrayList<String> ans = new ArrayList<String>();

				for (int i = 0; i < fore; i++){

					// Tracing stuff
					if (tracingOn){
						if (i == 0){
							System.out.println("  Answers (" + answerCount + ")");
						}
						if (i == answerCount){
							System.out.println("  Nameservers (" + nsCount + ")");
						}
						if (i == answerCount + nsCount){
							System.out.println("  Additional Information (" + additionalCount + ")");
						}
					}
					
					name = parseType2(dataStr);
					type = dataStr.readUnsignedShort();
	    			class1 = dataStr.readUnsignedShort();
	    			ttl = dataStr.readInt();
	    			dataLength = dataStr.readUnsignedShort();
	    			switch (type) {
	    				case 1:
	    					data1 = parseType1(dataStr, dataLength);
	    					break;
	    				case 2:
	    					data1 = parseType2(dataStr);
	    					break;
	    				case 5:
	    					data1 = parseType2(dataStr);
	    					cname1 = data1;
	    					break;
	    				case 28:
	    					data1 = parseType28(dataStr, dataLength);
	    					break;
	    				default:
	    					data1 = "";
	    					break;
	    			}
	    			String type00 = getType(type);

	    			// Tracing data
	    			if(tracingOn){
	    				System.out.format("       %-30s %-10d %-4s %s\n", name, ttl, type00, data1);
	    			}

	    			// Answers
	    			if(i < answerCount){
	    				String ansr = original_fqdn + " " + ttl + "    " + type00 + " " + data1;
	    				ans.add(ansr);
	    			}

	    			// Cname or Answer IP was found
	    			if(answerCount > 0){
	    				finished = true;
	    			}
	    			if(i == answerCount){
	    				ip = data1;
	    			}
				}
				for (int i = 0; i < answerCount; i++){
					System.out.println(ans.get(i));
				}
		    	dataStr.close();
		    }
	    }finally {
      		dataStr.close();
  		}
	}
}


