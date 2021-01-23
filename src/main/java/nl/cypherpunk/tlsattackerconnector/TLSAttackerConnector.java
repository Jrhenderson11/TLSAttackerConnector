package nl.cypherpunk.tlsattackerconnector;

import java.io.BufferedReader;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.io.FileReader;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import javax.xml.bind.JAXBException;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.config.Configurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;

import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler;
import de.rub.nds.tlsattacker.transport.exception.InvalidTransportHandlerStateException;
import de.rub.nds.tlsattacker.transport.socket.SocketState;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificatePair;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.RecordCryptoComputations;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.action.ActivateEncryptionOnlyAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeMasterSecretAction;
import de.rub.nds.tlsattacker.core.workflow.action.FlushSessionCacheAction;
import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;

import javax.security.cert.X509Certificate;
import java.io.ByteArrayOutputStream;
/**
 * @author Joeri de Ruiter (joeri@cs.ru.nl)
 *
 */
public class TLSAttackerConnector {
	static String SYMBOL_CONNECTION_CLOSED = "ConnectionClosed";
	static String SYMBOL_RESET = "RESET";

	HashMap<String, Integer> timeoutDict = new HashMap<>();

	Config config;
	State state;
	HashMap<String, WorkflowTrace> messages = new HashMap<>();

	@Parameter(names = {"--listen", "-l"}, description = "Listen port")
	int listenPort = 6666;
	@Parameter(names = {"--targetHost", "-tH"}, description = "Target host")
	String targetHostname = "localhost";
	@Parameter(names = {"--targetPort", "-tP"}, description = "Target port")
	int targetPort = 4500;
	@Parameter(names = {"--timeout", "-t"}, description = "Timeout")
	int timeout = 100;

	@Parameter(names = {"--startupDelay"}, description = "Wait this many milliseconds before startup. Useful when the system under test still needs to initialise.")
	int startupDelay = 0;

	@Parameter(names = {"--cipherSuite", "-cS"}, description = "Comma-separated list of ciphersuites to use. If none is provided this will default to TLS_RSA_WITH_AES_128_CBC_SHA256.")
	List<String> cipherSuiteStrings = new ArrayList<>();

	@Parameter(names = {"--protocolVersion", "-pV"}, description = "TLS version to use")
	String protocolVersionString = "TLS12";
	ProtocolVersion protocolVersion;

	@Parameter(names = {"--compressionMethod", "-cM"}, description = "CompressionMethod to use")
	String compressionMethodString = "NULL";

	@Parameter(names = {"--messageDir", "-mD"}, description = "Directory to load messages from")
	String messageDir = "messages";

	@Parameter(names = {"--help", "-h"}, description = "Display help", help = true)
	private boolean help;
	@Parameter(names = {"--test"}, description = "Run test handshake")
	private boolean test;

	@Parameter(names = {"--merge-application"}, description = "Merge successive APPLICATION messages into one message.")
	private boolean mergeApplication = false;

	@Parameter(names = {"--testCipherSuites"}, description = "Try to determine which CipherSuites are supported")
	private boolean testCipherSuites;
	@Parameter(names = {"--listMessages"}, description = "List all loaded messages")
	private boolean listMessages;

	/**
	 * Create the TLS-Attacker connector
	 *
	 */
	public TLSAttackerConnector() {
		// Add BouncyCastle, otherwise encryption will be invalid and it's not possible to perform a valid handshake
		Security.addProvider(new BouncyCastleProvider());
		UnlimitedStrengthEnabler.enable();

		// Disable logging
		Configurator.setAllLevels("de.rub.nds.tlsattacker", Level.OFF);
	}

	/**
	 * Intialise the TLS-Attacker connector
	 *
	 * @throws Exception
	 */
	public void initialise() throws Exception {
		// Configure TLS-Attacker
		config = Config.createConfig();
		config.setEnforceSettings(false);

		// Configure hosts
		OutboundConnection clientConnection = new OutboundConnection(targetPort,  targetHostname);
		
		// Timeout that is used when waiting for incoming messages
		clientConnection.setTimeout(timeout);
		config.setDefaultClientConnection(clientConnection);

		// Parse provided CipherSuite
		List<CipherSuite> cipherSuites = new LinkedList<>();
		for(String cipherSuiteString: cipherSuiteStrings) {
			try {
				cipherSuites.add(CipherSuite.valueOf(cipherSuiteString));
			}
			catch(java.lang.IllegalArgumentException e) {
				throw new Exception("Unknown CipherSuite " + cipherSuiteString);
			}
		}
		// If no CipherSuites are provided, set the default
		if(cipherSuites.size() == 0) {
			cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
		}

		// Parse CompressionMethod
		CompressionMethod compressionMethod;
		try {
			compressionMethod = CompressionMethod.valueOf(compressionMethodString);
		}
		catch(java.lang.IllegalArgumentException e) {
			throw new Exception("Unknown CompressionMethod " + compressionMethodString);
		}

		// TLS specific settings

		// Set TLS version
		protocolVersion = ProtocolVersion.fromString(protocolVersionString);
		config.setHighestProtocolVersion(protocolVersion);
		config.setDefaultSelectedProtocolVersion(protocolVersion);
		config.setDefaultHighestClientProtocolVersion(protocolVersion);

		// Set default selected CipherSuite. This will be the first in the list of specified CipherSuites, which will always contain at least one element
		config.setDefaultSelectedCipherSuite(cipherSuites.get(0));

		// Set the list of supported cipher suites
		config.setDefaultClientSupportedCiphersuites(cipherSuites);

		// Set supported compression algorithms
		List<CompressionMethod> compressionMethods = new LinkedList<>();
		compressionMethods.add(compressionMethod);
		config.setDefaultClientSupportedCompressionMethods(compressionMethods);

		// Set default DH parameters
		config.setDefaultClientDhGenerator(new BigInteger("2"));
		config.setDefaultClientDhModulus(new BigInteger("6668014432879854274002278852208614463049243575172486268847999412414761893973482255240669516874141524239224030057949495697186951824868185545819975637245503840103415249493026666167468715286478870340074507098367006866803177055300900777576918011"));
		config.setDefaultClientDhPrivateKey(new BigInteger("30757838539894352412510553993926388250692636687493810307136098911018166940950"));
		config.setDefaultClientDhPublicKey(new BigInteger("6668014432879854274002278852208614463049243575172486268847999412414761893973482255240669516874141524239224030057949495697186951824868185545819975637245503840103415249493026666167468715286478870340074507098367006866803177055300900777576918011"));
		config.setDefaultServerDhPrivateKey(new BigInteger("30757838539894352412510553993926388250692636687493810307136098911018166940950"));
		config.setDefaultServerDhPublicKey(new BigInteger("6668014432879854274002278852208614463049243575172486268847999412414761893973482255240669516874141524239224030057949495697186951824868185545819975637245503840103415249493026666167468715286478870340074507098367006866803177055300900777576918011"));

		// remove session id too?
		config.setDefaultClientSessionId(new byte[] {});
		config.setDefaultServerSessionId(new byte[] {});
		config.setAddRenegotiationInfoExtension(false);
		
		config.setDefaultClientRSAModulus(new BigInteger("00964c7496d43ef3ca977f3fc6fc4e9955594f7865b0e85cc5a07e4c2d23427f01727631a5f4211b386dfc541550a2c928c56a21e7ac48bffb68f9ce8eba1c84b057056368989dd7a25534c18e3b796a4440cb23e56fe4bf2d306d02ba5b73d3011e2c5e2803aae655846abce9e445ac2ea3458fc27ea6d74cae3d8515d0dbb750391282ffac9ff5ce8d1f87865ae5997cc944e99e67d61599c18058998e8d405661832d30a7338d82626999b05492037f98170cf55d47f819dc313d0b48bf3079167e9c51174ca4ed814f9a5a66c6396e98edd184e002eb01324fc75dc9d806de140d3284b68fe4fe4c3ed804b352a339cce53db9ccdf194bdffce45703c7212449c12f920ec8b9e03361c5d1a12e0903d52012f2fc1d95664b0bfe31efd656a9d88a3203bc6e6e88a09f1b45b7d89cf3fbe5e6794f47cb19ab5e43ae91c992b8ebb7129b441183c5cccfeaf22437b8490653933a2a6ccfa736968b676a7ce99240db3286313df50e57049708743284795a7bc964e03fab33df28e788a2bf53684741d77c4cab8d4891b5d218ec0ff4986c9611ad815e703b2a7b08954406cb561edff65a99684984098a73016b0eb6673333095f3e3ed3b3687e9164135423be37f4a79334237cdd08247b509f39256e650e9e35760a376a63e711ad002d824c528feff23c036ca59083e9df94650089a218a91f895c83fa941661fab639c9e9", 16));
		config.setDefaultClientRSAPrivateKey(new BigInteger("458533e098684e0805af5c66c449eeeee592b6d402d2582729a781c0d73068e2d879075a05e4525cf5b2e389c074abab6a353f5d93f94aa415d886ccca156ae2ce3db5cfa9d848e7d395c579eed4a86ccdb3a8f4f59ecf372dd11e93e8bd587a89e467e10661448d85e4816186af1b87af09fc0730e2277056a02a30ff1cc25c1f2a0ae20c8d28fbd39723eee7989038823897ff277485254bb5fc457b04a71fcd97098e19a8e4e9cc6fa02149dd08353aba5eca17cdb45af1d8ecad8d86b1fb30867bf39e5d5b64688dd38dc1402b4c96fc5a0fa6367351685e328f954f914da3e4bedb583e92e3758d140a888fcee46b7c15e31d7a8c8ee61a69dc3de91bd0a1ba5bff72623eb5d339cedc548130e571690a100e2ccea9a76cf7be428b5528f27a52d701af0df02773fa7624dd96a39f29f12905995b35cbed67e8847e69cd120de5750cb81ea9bc73910a6699e21d089d4d253695d4aeed33e23e4540ce563851a26904808e5bd319c4af0b8b7e7c2faca9c0feb152d94b95b390030f4b06781e65f16a97ab76030ad4569c4d6159116ee201ccc2ef04def8b2f60942f63a2c7bfcd452181edc117b0d10a3600b5b2abcbb25f92c787f29f044f6e6b4637fd0c2bea02bac1862a2c81be84b6fe5f685278e553f3411b2aa4c0b0761edab5408f2323297540f0f57b2a6e435cf762bd3264f5feb7a114c76bbb025886f10a9", 16));

		// Setup timeout dictionary
		this.timeoutDict.put("ClientHelloRSAReset", this.timeout);
		this.timeoutDict.put("ClientKeyExchange", 100);
		this.timeoutDict.put("EmptyCertificate", 100);
		this.timeoutDict.put("ChangeCipherSpec", 100);
		this.timeoutDict.put("Finished", 200);
		this.timeoutDict.put("ApplicationData", this.timeout);
		this.timeoutDict.put("ApplicationDataEmpty", 100);
		this.timeoutDict.put("CertificateStatus", 100);
		this.timeoutDict.put("ClientCertificateValid", 100);
		this.timeoutDict.put("ClientCertificateInvalid", 100);
		this.timeoutDict.put("ClientCertificateVerify", 100);

		//initialiseSession();
	}

	public static byte[] getbytes24(int val) {
		byte[] out = new byte[3];
		out[0] = (byte)(0xFF & (val >>> 16));
		out[1] = (byte)(0xFF & (val >>> 8));
		out[2] = (byte)(0xFF & val);
		return out;
	}

	private byte[] getCertificateChainBytes(String fileName) {
		ByteArrayOutputStream outStream = new ByteArrayOutputStream();

		try {
			ByteArrayOutputStream chainStream = new ByteArrayOutputStream();

			InputStream inStream = new FileInputStream(fileName);
			X509Certificate cert1 = X509Certificate.getInstance(inStream);
			inStream.close();

			chainStream.write(cert1.getEncoded());
			
			byte[] chain = chainStream.toByteArray();
			
			outStream.write(chain);

		} catch (Exception ex) {
			System.out.println(ex);
		}
		
		return outStream.toByteArray();
	}

	/**
	 * Reset the connection with the TLS implementation by closing the current socket and initialising a new session
	 *
	 * @throws IOException
	 */
	public void reset() throws IOException {
		close();
		initialiseSession();
	}

	/**
	 * Close the current connection
	 * @throws IOException
	 */
	public void close() throws IOException {
		try {
			state.getTlsContext().getTransportHandler().closeConnection();
		} catch (Exception e) {
		}
	}

	/**
	 * Initialise a TLS connection by configuring a new context and connecting to the server
	 *
	 * @throws IOException
	 */
	public void initialiseSession() throws IOException {
		state = new State(config);

		TlsContext context = state.getTlsContext();

		//TransportHandler transporthandler = TransportHandlerFactory.createTransportHandler(config.getConnectionEnd());
		ConnectorTransportHandler transporthandler = new ConnectorTransportHandler(config.getDefaultClientConnection().getTimeout(), config.getDefaultClientConnection().getHostname(), config.getDefaultClientConnection().getPort());
		context.setTransportHandler(transporthandler);

		context.initTransportHandler();
		context.initRecordLayer();
	}

	/**
	 * Send the provided message to the TLS implementation
	 *
	 * @param message ProtocolMessage to be sent
	 */
	protected void sendMessage(ProtocolMessage message) {
		List<ProtocolMessage> traceMessages = new LinkedList<>();
		traceMessages.add(message);

		SendAction action = new SendAction(traceMessages);

		// Need to normalize otherwise an exception is thrown about no connection existing with alias 'null'
		action.normalize();
		action.execute(state);
	}

	/**
	 * Execute the provided trace
	 *
	 * @param trace WorkflowTrace to be executed
	 */
	protected void sendMessage(WorkflowTrace trace) {
		for(TlsAction tlsAction: trace.getTlsActions()) {
			
			tlsAction.normalize();
			tlsAction.execute(state);
		}

		// Reset trace so we can execute it again
		trace.reset();
	}

	/**
	 * Receive message on the TLS connection
	 *
	 * @return A string representation of the message types that were received
	 * @throws IOException
	 */
	protected String receiveMessages() throws IOException {
		// First check if the socket is still open
		if(state.getTlsContext().getTransportHandler().isClosed()) {
		   return SYMBOL_CONNECTION_CLOSED;
		}

		LinkedList<String> receivedMessages = new LinkedList<>();
		ReceiveAction action = new ReceiveAction();
		// Need to normalize otherwise an exception is thrown about no connection existing with alias 'null'
		action.normalize();
		// Perform the actual receiving of the message
		action.execute(state);

		String outputMessage;

		// Check for every record if the MAC is valid. If it is not, do not
		// continue reading it since its contents might be illegible.

		for(AbstractRecord abstractRecord: action.getReceivedRecords()) {
			try {

				Record record = (Record) abstractRecord;

				if(record == null) {
					continue;
				}

				if(record.getComputations() == null) {
					continue;
				}

				if(record.getComputations().getMacValid() == null) {
					continue;
				}

				if(!record.getComputations().getMacValid()) {
					
					// try {
					// 	if(((ClientTcpTransportHandler)state.getTlsContext().getTransportHandler()).getSocketState() == SocketState.CLOSED) {
					// 		return "DecryptError";
					// 	}
					// } catch (InvalidTransportHandlerStateException ex) {
					// 	System.out.println(" InvalidTransportHandlerStateException 1");
					// 	return "DecryptError";
					// }
		// 		            return "DecryptError";
					if(state.getTlsContext().getTransportHandler().isClosed()) {
						return "InvalidMAC" + SYMBOL_CONNECTION_CLOSED;
					}
					return "InvalidMAC";
				}
			} catch (Exception ex) {
				throw(ex);
				
			}
		}

		// Iterate over all received messages and build a string containing their respective types
		for(ProtocolMessage message: action.getReceivedMessages()) {
			if(message.getProtocolMessageType() == ProtocolMessageType.ALERT) {
				AlertMessage alert = (AlertMessage)message;
				AlertLevel level = AlertLevel.getAlertLevel(alert.getLevel().getValue());

				AlertDescription description = AlertDescription.getAlertDescription(alert.getDescription().getValue());

				outputMessage = "Alert" + level.getValue() + ".";
				if(description == null) {
					outputMessage += "UNKNOWN";
				} else {
					outputMessage += description.getValue();
				}
			}
			else if (message.toCompactString().equals("UNKNOWN_MESSAGE") && state.getTlsContext().getRecordLayer().getDecryptorCipher() != null) {
				// Count this as a decryption error: we have a decrypt cipher but it gave an unknown message
				outputMessage = "DecryptError";
			} else {
				outputMessage = message.toCompactString();
			}

			if(mergeApplication && receivedMessages.peekLast() == "APPLICATION" && outputMessage == "APPLICATION") {
				// In this very specific case, the message should not be added
				// to the receivedMessages array. Namely:
				// - The user passed the --merge-application argument
				// - The last message received was APPLICATION
				// - The current message received is also APPLICATION
			}
			else {
				receivedMessages.add(outputMessage);
			}

		}

		// Finally check again :)))
		try {
			if(((ClientTcpTransportHandler)state.getTlsContext().getTransportHandler()).getSocketState() == SocketState.CLOSED) {
				receivedMessages.add(SYMBOL_CONNECTION_CLOSED);
			}
		} catch (InvalidTransportHandlerStateException ex) {
			return SYMBOL_CONNECTION_CLOSED;
		}
		

		if(receivedMessages.size() > 0) {
			return String.join("", receivedMessages);
		} else {
			return "Empty";
		}
	}

	/**
	 * Send a message of the provided type and return the types of the response messages
	 *
	 * @param inputSymbol A string indicating which type of message to send
	 * @return A string representation of the message types that were received
	 * @throws Exception
	 */
	public String processInput(String inputSymbol) throws Exception {
		// Upon receiving the special input symbol RESET, we reset the system
		if(inputSymbol.equals(SYMBOL_RESET)) {
			reset();
			return "";
		}

		// Check if the socket is already closed, in which case we don't have to bother trying to send data out
		if(state.getTlsContext().getTransportHandler().isClosed()) {
			return SYMBOL_CONNECTION_CLOSED;
		}

		// Set dynamic timeout
		//config.getDefaultClientConnection().setTimeout(this.timeoutDict.get(inputSymbol));

		//System.out.println(config.getDefaultClientConnection().getTimeout());
		messages.put("ClientKeyExchange", createSendActionTrace(new RSAClientKeyExchangeMessage(config)));

		// Process the regular input symbols


		// Process the regular input symbols
		if (inputSymbol.equals("ClientHelloRSAReset") && state.getTlsContext() != null && state.getTlsContext().getDigest().getRawBytes().length != 0) {
			state.getTlsContext().getDigest().reset();
			
		}

		if (inputSymbol.equals("ClientHelloRSAReset")) {
			// state.getTlsContext().setServerSessionId(new byte[] {});
			// state.getTlsContext().setClientSessionId(new byte[] {});
			state.getTlsContext().setRenegotiationInfo(new byte[] {});
			//messages.put("ClientHelloRSAReset", createSendActionTrace(new ClientHelloMessage(config)));
		}
		

		if(messages.containsKey(inputSymbol)) {
			sendMessage(messages.get(inputSymbol));
		} else {
			throw new Exception("Unknown input symbol: " + inputSymbol);
		}

		return receiveMessages();
	}

	/**
	 * Start listening on the provided to port for a connection to provide input symbols and return output symbols. Only one connection is accepted at the moment.
	 *
	 * @throws Exception
	 */
	public void startListening() throws Exception {
		ServerSocket serverSocket = new ServerSocket(listenPort);
		System.out.println("Listening on port " + listenPort);

		Socket clientSocket = serverSocket.accept();
		clientSocket.setTcpNoDelay(true);

		PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
		BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

		String input, output;

		while((input = in.readLine()) != null) {
			output = processInput(input);
			System.out.println(input + " / " + output);
			out.println(output);
			out.flush();
		}

		clientSocket.close();
		serverSocket.close();
	}
	/**
	 * Take a ProtocolMessage and wrap it in a SendAction and wrap that in a WorkflowTrace
	*/
	private WorkflowTrace createSendActionTrace(ProtocolMessage message) {
		SendAction action = new SendAction(message);

		WorkflowTrace trace = new WorkflowTrace();
		trace.addTlsAction(action);

		return trace;
	}

	/**
	 * Load messages from the specified directory. Each message should be in a separate file with the xml extension and contain workflow trace in XML format.
	 *
	 * @param filename Path to messages from
	 * @throws Exception
	 */
	public void loadMessages(String fileName) throws Exception {


		//HashMap<String, WorkflowTrace>

		String messageName = "";
		try (BufferedReader br = new BufferedReader(new FileReader(fileName))) {
		
			while ((messageName = br.readLine()) != null) {
				
				ProtocolMessage message = (ProtocolMessage)Class.forName("de.rub.nds.tlsattacker.core.protocol.message." + messageName + "Message").newInstance();
				messages.put(messageName, createSendActionTrace(message));
			}

			WorkflowTrace CCStrace = new WorkflowTrace();
			byte[] emptyMasterSecret = new byte[0];
			
			CCStrace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(config)));
			//CCStrace.addTlsAction(new ChangeMasterSecretAction(emptyMasterSecret));
			CCStrace.addTlsAction(new ActivateEncryptionOnlyAction());

			
			messages.put("ChangeCipherSpec", CCStrace);

			
			// WorkflowTrace CHnoResumptionTrace = new WorkflowTrace();
			// CHnoResumptionTrace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
			
			// // add this to wipe knowledge of previous sessions :(
			// CHnoResumptionTrace.addTlsAction(new FlushSessionCacheAction());
			// messages.put("ClientHelloRSAReset", CHnoResumptionTrace);

			messages.put("CertificateStatus", createSendActionTrace(new CertificateStatusMessage(config)));
			messages.put("SSL2ClientHello", createSendActionTrace(new SSL2ClientHelloMessage(config)));

			
			CertificateMessage validCertificateMessage = new CertificateMessage(config);
			List<CertificatePair> certificatePairsList = new LinkedList<>();
			CertificatePair certificatePair = new CertificatePair(getCertificateChainBytes("/home/james/Documents/CTF/project/tls/openssl/server_key/self_signed.pem"));
			certificatePairsList.add(certificatePair);
			validCertificateMessage.setCertificatesList(certificatePairsList);
			messages.put("ClientCertificateValid", createSendActionTrace(validCertificateMessage));

			CertificateMessage invalidCertificateMessage = new CertificateMessage(config);
			List<CertificatePair> invalidCertificatePairsList = new LinkedList<>();
			CertificatePair invalidCertificatePair = new CertificatePair(getCertificateChainBytes("/home/james/Documents/CTF/project/tls/openssl/server_key/client.pem"));
			invalidCertificatePairsList.add(invalidCertificatePair);
			validCertificateMessage.setCertificatesList(invalidCertificatePairsList);
			messages.put("ClientCertificateInvalid", createSendActionTrace(invalidCertificateMessage));

			messages.put("ClientCertificateVerify", createSendActionTrace(new CertificateVerifyMessage(config)));

			messages.put("CertificateRequest", createSendActionTrace(new CertificateRequestMessage(config)));
			messages.put("HelloVerifyRequest", createSendActionTrace(new HelloVerifyRequestMessage(config)));
			messages.put("DHClientKeyExchange", createSendActionTrace(new DHClientKeyExchangeMessage(config)));
			messages.put("DHEServerKeyExchange", createSendActionTrace(new DHEServerKeyExchangeMessage(config)));
			messages.put("ECDHClientKeyExchange", createSendActionTrace(new ECDHClientKeyExchangeMessage(config)));
			messages.put("ECDHEServerKeyExchange", createSendActionTrace(new ECDHEServerKeyExchangeMessage(config)));
			messages.put("ServerHelloDone", createSendActionTrace(new ServerHelloDoneMessage(config)));
			messages.put("ServerHello", createSendActionTrace(new ServerHelloMessage(config)));
			messages.put("Alert", createSendActionTrace(new AlertMessage(config)));
			messages.put("SSL2ClientHello", createSendActionTrace(new SSL2ClientHelloMessage(config)));
			messages.put("SSL2ServerHello", createSendActionTrace(new SSL2ServerHelloMessage(config)));
			messages.put("HelloRequest", createSendActionTrace(new HelloRequestMessage(config)));
			messages.put("EncryptedExtensionMessage", createSendActionTrace(new EncryptedExtensionsMessage(config)));
			messages.put("HelloRetryRequest", createSendActionTrace(new HelloRetryRequestMessage(config)));

			messages.put("ClientHelloRSAReset", createSendActionTrace(new ClientHelloMessage(config)));

			RSAClientKeyExchangeMessage clientKeyExchangeMessage = new RSAClientKeyExchangeMessage(config);
			messages.put("ClientKeyExchange", createSendActionTrace(clientKeyExchangeMessage));

			ApplicationMessage applicationDataMessage = new ApplicationMessage(config);
			applicationDataMessage.setDataConfig("GET / HTTP/1.0\n\n".getBytes());
			messages.put("ApplicationData", createSendActionTrace(applicationDataMessage));
			
			ApplicationMessage applicationDataMessageEmpty = new ApplicationMessage(config);
			byte[] empty = {};
			applicationDataMessageEmpty.setDataConfig(new byte[0]);
			messages.put("ApplicationDataEmpty", createSendActionTrace(applicationDataMessageEmpty));

			CertificateMessage certificateMessage = new CertificateMessage(config);
			certificateMessage.setCertificatesListLength(0);
			byte[] list = {};
			certificateMessage.setCertificatesListBytes(list);
			messages.put("EmptyCertificate", createSendActionTrace(certificateMessage));

			

		} catch (ClassNotFoundException e) {
			System.out.println("Cannot create message: " + messageName);
			e.printStackTrace();
			System.exit(-1);
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	/**
	 * @return A list of all loaded messages that can be used as input symbols
	 */
	public String[] listMessages() {
		String[] list = new String[messages.size()];
		int i = 0;
		for(String name: messages.keySet()) {
			list[i++] = name;
		}
		return list;
	}

	public static void main(String ... argv) {
		try {
			TLSAttackerConnector connector = new TLSAttackerConnector();

			// Parse commandline arguments
			JCommander commander = JCommander.newBuilder()
			.addObject(connector)
			.build();
			commander.parse(argv);

			if (connector.help) {
				commander.usage();
				return;
			}

			// Wait for the duration of `startupDelay`
			Thread.sleep(connector.startupDelay);

			// Initialise the connector after the arguments are set
			connector.initialise();

			connector.loadMessages(connector.messageDir);

			if(connector.listMessages) {
				System.out.println("========================================");
				System.out.println("Loaded messages:");
				for(String msg: connector.listMessages()) {
					System.out.println(msg);
				}
				System.out.println("========================================");
			}

			if(connector.test) {
				String[] mlist = {"CertificateRequest",
								  "HelloVerifyRequest",
								  "DHClientKeyExchange",
								  "DHEServerKeyExchange",
								  "ECDHClientKeyExchange",
								  "ECDHEServerKeyExchange",
								  "ServerHelloDone",
								  "Alert",
								  "SSL2ClientHello",
								  //"SSL2ServerHello", = Unsupported?
								  "HelloRequest",
								  "EncryptedExtensionMessage",
								  //"HelloRetryRequest", =  Goes batshit crazy
								  "ServerHello"};
				
				for (String m : mlist) {

					connector.processInput("RESET");
					System.out.println("ClientHello: " + connector.processInput("ClientHelloRSAReset"));
					//System.out.println("ClientHello: " + connector.processInput("ClientHelloRSAReset"));
					
					// Force the negotiated TLS version to be the one specified
					// through the parameters. Otherwise, a test if an
					// implementation supports a specific version will be
					// unreliable.
					connector.state.getTlsContext().setSelectedProtocolVersion(connector.protocolVersion);

					System.out.println("ClientCertificateValid: " + connector.processInput("ClientCertificateValid"));

					CipherSuite selectedCipherSuite = connector.state.getTlsContext().getSelectedCipherSuite();
					if(selectedCipherSuite == null) {
						System.out.println("RSAClientKeyExchange: " + connector.processInput("RSAClientKeyExchange"));
					}
					else if(selectedCipherSuite.name().contains("ECDH")) {
						System.out.println("ECDHClientKeyExchange: " + connector.processInput("ECDHClientKeyExchange"));
					} else if(selectedCipherSuite.name().contains("DH")) {
						System.out.println("DHClientKeyExchange: " + connector.processInput("DHClientKeyExchange"));
					} else if(selectedCipherSuite.name().contains("RSA")) {
						System.out.println("RSAClientKeyExchange: " + connector.processInput("RSAClientKeyExchange"));
					}

					System.out.println("ClientCertificateVerify: " + connector.processInput("ClientCertificateVerify"));

					System.out.println("ChangeCipherSpec: " + connector.processInput("ChangeCipherSpec"));
					System.out.println("Finished: " + connector.processInput("Finished"));

					System.out.println(m + ": " +  connector.processInput(m));

					System.out.println("ApplicationData: " + connector.processInput("ApplicationData"));
					System.out.println("ApplicationDataEmpty: " + connector.processInput("ApplicationDataEmpty"));
				}
			}
			else if(connector.testCipherSuites) {
				for(CipherSuite cs: CipherSuite.values()) {
					List<CipherSuite> cipherSuites = new ArrayList<>();
					cipherSuites.add(cs);
					connector.config.setDefaultSelectedCipherSuite(cs);
					connector.config.setDefaultClientSupportedCiphersuites(cipherSuites);

					try {
						connector.processInput("RESET");
						System.out.println(cs.name() + " " + connector.processInput("ClientHello"));
					} catch(java.lang.UnsupportedOperationException | java.lang.IllegalArgumentException e) {
						System.out.println(cs.name() + " UNSUPPORTED");
					}
				}
			} else {
				connector.startListening();
			}
		} catch(Exception e) {
			System.err.println("Error occured: " + e.getMessage());
			e.printStackTrace(System.err);
			System.exit(1);
		}
	}
}