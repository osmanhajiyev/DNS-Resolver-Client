
import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.util.Random;
// new
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.SocketException;

/**
* 
*/

/**
* Written by: Osman Hajiyev and Peder Shirley with the guidance from Professor Donald Acton for CS317
* Feel free to modify and rearrange code as you see fit
*/
public class DNSlookup {

		static final int MIN_PERMITTED_ARGUMENT_COUNT = 2;
		static final int MAX_PERMITTED_ARGUMENT_COUNT = 3;

	/**
	* @param args
	*/
	public static void main(String[] args) throws Exception {

	int queryNum = 30;
	String nextfqdn;
	String fqdn;
	DNSResponse response; // Just to force compilation
	int argCount = args.length;
	boolean tracingOn = false;
	boolean IPV6Query = false;
	InetAddress rootNameServer; //199.7.83.42
	//new
	InetAddress nextServer;
	int dnsPort = 53;
	DatagramSocket socket;
	DatagramPacket packet;
	byte[] sendBuf = new byte[512];

	ByteArrayOutputStream byteStr = new ByteArrayOutputStream();
	DataOutputStream dataStr = new DataOutputStream(byteStr);


	if (argCount < MIN_PERMITTED_ARGUMENT_COUNT || argCount > MAX_PERMITTED_ARGUMENT_COUNT) {
		usage();
		return;
	}

	rootNameServer = InetAddress.getByName(args[0]);
	fqdn = args[1];

	if (argCount == 3) {  // option provided
		if (args[2].equals("-t"))
			tracingOn = true;
		else if (args[2].equals("-6"))
			IPV6Query = true;
		else if (args[2].equals("-t6")) {
			tracingOn = true;
			IPV6Query = true;
	} else  { // option present but wasn't valid option
	usage();
	return;
	}
	}

	// Start adding code here to initiate the lookup

	// Header ==================================
	// 0-15: Query ID
	nextfqdn = fqdn;
	nextServer = rootNameServer;
	while(true){
		Random randall = new Random();
		int qid = randall.nextInt(65535 + 1);
		dataStr.writeShort(qid);

		// 0: QR | 1-3: Opcode | 5: AA | 6: TC | 7: RD |8: RA | 9-11: Z | 12-15: RCODE
		dataStr.writeShort(0x0000);

		// 0-15: QD Count
		dataStr.writeShort(0x0001);

		// 0-15: AN Count
		dataStr.writeShort(0x0000);

		// 0-15: NS Count
		dataStr.writeShort(0x0000);

		// 0-15: AR Count
		dataStr.writeShort(0x0000);

		// Query ==================================
		// QNAME
		String[] fqdnSplit = nextfqdn.split("\\.");

		for (int i = 0; i < fqdnSplit.length; i++){
			byte[] fqdnByteForm = fqdnSplit[i].getBytes(); //"UTF-8" charset if needed
			//QNAME starter
			dataStr.writeByte(fqdnByteForm.length);
			//QNAME part
			dataStr.write(fqdnByteForm);
		} 

		// 0-7: endof QNAME
		dataStr.writeByte(0x00);

		// 0-15: QTYPE -Assumed 1 = A = a host address
		dataStr.writeShort(0x0001);

		// 0-15: QCLASS -Assumed 1 = IN = the internet
		dataStr.writeShort(0x0001);

		sendBuf = byteStr.toByteArray();

		//=========================================
		//Dump answer
		String code;
		code = "A";
		if (IPV6Query){
			code = "AAAA";
		}
		if (tracingOn) {
			System.out.println("Query ID     " + qid + " " + nextfqdn 
				+ "  "+code+" --> " + nextServer.toString().split("/")[1]);
		}

		//Send request
		// Initialize Sockets for sending
		socket = new DatagramSocket();
		packet = new DatagramPacket(sendBuf, sendBuf.length, nextServer, dnsPort);
		// Send packet
		socket.send(packet);

		// Receive response
		byte[] getBuf = new byte[1024];
		DatagramPacket getPacket = new DatagramPacket(getBuf, getBuf.length);
		socket.setSoTimeout(5000);
		try{
			socket.receive(getPacket);
		} catch (SocketException | SocketTimeoutException e) {
			try{
				socket.setSoTimeout(5000);
				socket.receive(getPacket);
			} catch (SocketException | SocketTimeoutException e1) {
				System.out.println(fqdn + " -2	A 0.0.0.0");
				break;
			}
		}
		// receive packet
		
		DNSResponse responseObject;

		responseObject = new DNSResponse(getBuf, getBuf.length, tracingOn, fqdn);

		if(queryNum == 0){
			System.out.println(fqdn + " -3	A 0.0.0.0");
			break;
		}

		if(responseObject.finished()){
			if(responseObject.cname().equals("")){
				// If answer IP was found then output and finish
				break;
			} else {
				// If cname clue was found then start looking for cname in rootServer
				nextfqdn = responseObject.cname();
				nextServer = rootNameServer;
				byteStr = new ByteArrayOutputStream();
	    		dataStr = new DataOutputStream(byteStr);
	    		queryNum = queryNum - 1;
			}
		} else {
			byteStr = new ByteArrayOutputStream();
		    dataStr = new DataOutputStream(byteStr);
	    	nextServer = InetAddress.getByName(responseObject.getNextServer());
	    	queryNum = queryNum - 1;
		}


	}
	}



	// Input clarification for the user
	private static void usage() {
		System.out.println("Usage: java -jar DNSlookup.jar rootDNS name [-6|-t|t6]");
		System.out.println("   where");
		System.out.println("       rootDNS - the IP address (in dotted form) of the root");
		System.out.println("                 DNS server you are to start your search at");
		System.out.println("       name    - fully qualified domain name to lookup");
		System.out.println("       -6      - return an IPV6 address");
		System.out.println("       -t      - trace the queries made and responses received");
		System.out.println("       -t6     - trace the queries made, responses received and return an IPV6 address");
	}

}



