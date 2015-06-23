package net.sumppen.whatsapi4j;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import net.sumppen.whatsapi4j.async.WhatsAppChannelHandler;
import net.sumppen.whatsapi4j.async.WhatsAppDecoder;
import net.sumppen.whatsapi4j.async.WhatsAppEncoder;
import net.sumppen.whatsapi4j.events.Event;
import net.sumppen.whatsapi4j.events.EventType;
import net.sumppen.whatsapi4j.message.*;
import net.sumppen.whatsapi4j.operation.AccountOps;
import net.sumppen.whatsapi4j.operation.GroupOps;
import net.sumppen.whatsapi4j.operation.MediaOps;
import net.sumppen.whatsapi4j.operation.TextOps;
import net.sumppen.whatsapi4j.tools.BinHex;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;


public class WhatsApi {

    private static final String RELEASE_TOKEN_CONST = "PdA2DJyKoUrwLw1Bg6EIhzh502dF9noR9uFCllGk";
    private static final String RELEASE_TIME = "1419900749520";
    private final int PORT = 443;                                      // The port of the WhatsApp server.
    private final int TIMEOUT_SEC = 2;                                  // The timeout for the connection with the WhatsApp servers.
    private final String WHATSAPP_CHECK_HOST = "v.whatsapp.net/v2/exist";  // The check credentials host.
    public static final String WHATSAPP_GROUP_SERVER = "g.us";                   // The Group server hostname
    private final String WHATSAPP_HOST = "c.whatsapp.net";                 // The hostname of the WhatsApp server.
    private final String WHATSAPP_REGISTER_HOST = "v.whatsapp.net/v2/register"; // The register code host.
    private final String WHATSAPP_REQUEST_HOST = "v.whatsapp.net/v2/code";      // The request code host.
    public static final String WHATSAPP_SERVER = "s.whatsapp.net";               // The hostname used to login/send messages.
    private final String WHATSAPP_DEVICE = "S40";                      // The device name.
    private final String WHATSAPP_VER = "2.12.81";                // The WhatsApp version.
    private final String WHATSAPP_USER_AGENT = "WhatsApp/2.12.81 S40Version/14.26 Device/Nokia302";// User agent used in request/registration code.
    private final String WHATSAPP_VER_CHECKER = "https://coderus.openrepos.net/whitesoft/whatsapp_version"; // Check WhatsApp version

    private final static Logger log = LoggerFactory.getLogger(WhatsApi.class);
    private String identity;
    private final String name;
    private final String phoneNumber;
    private LoginStatus loginStatus;
    private String password;

    private byte[] challengeData;
    private KeyStream inputKey;
    private KeyStream outputKey;
    //ver aca que onda.
    // private List<String> serverReceivedId = new LinkedList<String>();
    // private List<ProtocolNode> messageQueue = new LinkedList<ProtocolNode>();

    private String lastId;
    //private List<ProtocolNode> outQueue = new LinkedList<ProtocolNode>();
    private EventManager eventManager = new LoggingEventManager();
    private final List<Country> countries;
    private MessageProcessor processor = null;
    private String lastSendMsgId;


    private final AtomicLong messageCounter = new AtomicLong();
    private final EventLoopGroup workerGroup = new NioEventLoopGroup();
    private final Bootstrap b = new Bootstrap();
    private final WhatsAppEncoder encoder = new WhatsAppEncoder();
    private final WhatsAppDecoder decoder = new WhatsAppDecoder();
    private ChannelFuture f;

    private final Map<String, Map<String, Object>> mediaQueue = Maps.newConcurrentMap();

    private final TextOps textOps = new TextOps(this);
    private final MediaOps mediaOps = new MediaOps(this, mediaQueue);
    private final GroupOps groupOps = new GroupOps(this);
    private final AccountOps accountOps = new AccountOps(this);

    public TextOps text() {
        return textOps;
    }

    public MediaOps media() {
        return mediaOps;
    }

    public GroupOps group() {
        return groupOps;
    }

    public AccountOps account() {
        return accountOps;
    }

    public WhatsApi(String username, String identity, String nickname) throws NoSuchAlgorithmException, WhatsAppException, IOException {
        this.name = nickname;
        this.phoneNumber = username;
        try {
            if (!checkIdentity(identity)) {
                this.identity = buildIdentity(identity);
            } else {
                this.identity = identity;
            }
        } catch (UnsupportedEncodingException e) {
            throw new WhatsAppException(e);
        }
        this.loginStatus = LoginStatus.DISCONNECTED_STATUS;
        countries = readCountries();

        final WhatsAppChannelHandler whatsAppChannelHandler = new WhatsAppChannelHandler(this);
        b.group(workerGroup); // (2)
        b.channel(NioSocketChannel.class); // (3)
        b.option(ChannelOption.SO_KEEPALIVE, true); // (4)
        b.handler(new ChannelInitializer<SocketChannel>() {
            @Override
            public void initChannel(SocketChannel ch) throws Exception {
                ch.pipeline().addFirst(encoder);
                ch.pipeline().addLast(decoder);
                ch.pipeline().addLast(whatsAppChannelHandler);
            }
        });
    }


    /**
     * Register account on WhatsApp using the provided code.
     *
     * @return object
     * An object with server response.
     * - status: Account status.
     * - login: Phone number with country code.
     * - pw: Account password.
     * - type: Type of account.
     * - expiration: Expiration date in UNIX TimeStamp.
     * - kind: Kind of account.
     * - price: Formatted price of account.
     * - cost: Decimal amount of account.
     * - currency: Currency price of account.
     * - price_expiration: Price expiration in UNIX TimeStamp.
     * @throws WhatsAppException
     * @throws JSONException
     * @throws Exception
     */
    public JSONObject codeRegister(String code) throws WhatsAppException, JSONException {
        Map<String, String> phone;
        if ((phone = dissectPhone()) == null) {
            throw new WhatsAppException("The prived phone number is not valid.");
        }
        String countryCode = null;
        String langCode = null;
        if (countryCode == null) {
            if (phone.get("ISO3166") != null) {
                countryCode = phone.get("ISO3166");
            } else {
                countryCode = "US";
            }
        }
        if (langCode == null) {
            if (phone.get("ISO639") != null) {
                langCode = phone.get("ISO639");
            } else {
                langCode = "en";
            }
        }

        // Build the url.
        String host = "https://" + WHATSAPP_REGISTER_HOST;
        Map<String, String> query = new LinkedHashMap<String, String>();
        query.put("cc", phone.get("cc"));
        query.put("in", phone.get("phone"));
        query.put("lg", langCode);
        query.put("lc", countryCode);
        query.put("id", (identity == null ? "" : identity));
        query.put("code", code);
        //		query.put("c", "cookie");

        JSONObject response = getResponse(host, query);
        if (log.isDebugEnabled()) {
            log.debug(response.toString(1));
        }
        if (!response.getString("status").equals("ok")) {
            eventManager.fireCodeRegisterFailed(phoneNumber, response.getString("status"), response.getString("reason"), "");//response.getString("retry_after"));
            throw new WhatsAppException("An error occurred registering the registration code from WhatsApp.");
        } else {
            eventManager.fireCodeRegister(phoneNumber, response.getString("login"), response.getString("pw"), response.getString("type"), response.getString("expiration"),
                    response.getString("kind"), response.getString("price"), response.getString("cost"), response.getString("currency"), response.getString("price_expiration"));
        }

        return response;
    }

    /**
     * Request a registration code from WhatsApp.
     *
     * @return {@link JSONObject}
     * An object with server response.
     * - status: Status of the request (sent/fail).
     * - length: Registration code lenght.
     * - method: Used method.
     * - reason: Reason of the status (e.g. too_recent/missing_param/bad_param).
     * - param: The missing_param/bad_param.
     * - retry_after: Waiting time before requesting a new code.
     * @throws JSONException
     * @throws WhatsAppException
     * @throws UnsupportedEncodingException
     * @throws Exception
     */
    public JSONObject codeRequest(String method, String countryCode, String langCode) throws WhatsAppException, JSONException, UnsupportedEncodingException {
        if (method == null) {
            method = "sms";
        }
        Map<String, String> phone;
        if ((phone = dissectPhone()) == null) {
            throw new WhatsAppException("The prived phone number is not valid.");
        }

        if (countryCode == null) {
            if (phone.get("ISO3166") != null) {
                countryCode = phone.get("ISO3166");
            } else {
                countryCode = "US";
            }
        }
        if (langCode == null) {
            if (phone.get("ISO639") != null) {
                langCode = phone.get("ISO639");
            } else {
                langCode = "en";
            }
        }

        String token;
        try {
            token = generateRequestToken(phone.get("country"), phone.get("phone"));
        } catch (NoSuchAlgorithmException e) {
            throw new WhatsAppException(e);
        } catch (IOException e) {
            throw new WhatsAppException(e);
        }
        // Build the url.
        String host = "https://" + WHATSAPP_REQUEST_HOST;
        Map<String, String> query = new LinkedHashMap<String, String>();
        query.put("cc", phone.get("cc"));
        query.put("in", phone.get("phone"));
        //		query.put("to",phoneNumber);
        query.put("lg", langCode);
        query.put("lc", countryCode);
        query.put("method", method);
        //		query.put("mcc",phone.get("mcc"));
        //		query.put("mnc","001");
        query.put("sim_mcc", phone.get("mcc"));
        query.put("sim_mnc", "000");
        query.put("token", URLEncoder.encode(token, "iso-8859-1"));
        query.put("id", (identity == null ? "" : identity));

        JSONObject response = getResponse(host, query);
        if (log.isDebugEnabled()) {
            log.debug(response.toString(1));
        }
        if (!response.getString("status").equals("ok")) {
            if (response.getString("status").equals("sent")) {
                eventManager.fireCodeRequest(phoneNumber, method, response.getString("length"));
            } else {
                if (!response.isNull("reason") && response.getString("reason").equals("too_recent")) {
                    String retry_after = (response.has("retry_after") ? response.getString("retry_after") : null);
                    eventManager.fireCodeRequestFailedTooRecent(phoneNumber, method, response.getString("reason"), retry_after);
                    throw new WhatsAppException("Code already sent. Retry after " + retry_after + " seconds");
                } else {
                    eventManager.fireCodeRequestFailed(phoneNumber, method, response.getString("reason"), (response.has("param") ? response.getString("param") : null));
                    throw new WhatsAppException("There was a problem trying to request the code. Status=" + response.getString("status"));
                }
            }
        } else {
            eventManager.fireCodeRegister(phoneNumber, response.getString("login"), response.getString("pw"), response.getString("type"), response.getString("expiration"),
                    response.getString("kind"), response.getString("price"), response.getString("cost"), response.getString("currency"), response.getString("price_expiration"));
        }
        return response;
    }

    protected String generateRequestToken(String country, String phone) throws IOException, NoSuchAlgorithmException {
        return WhatsMediaUploader.md5(RELEASE_TOKEN_CONST + RELEASE_TIME + phone);
    }

    private byte[] hash(String algo, byte[] dataBytes) throws NoSuchAlgorithmException {
        MessageDigest md;

        md = MessageDigest.getInstance(algo);

        md.update(dataBytes, 0, dataBytes.length);
        byte[] mdbytes = md.digest();
        return mdbytes;
    }

    /**
     * Connect (create a socket) to the WhatsApp network.
     */
    public boolean connect() throws IOException, InterruptedException {
        f = b.connect(WHATSAPP_HOST, PORT).sync();
        log.debug("channel is open {}", f.channel().isOpen());
        return f.channel().isOpen();
    }

    /**
     * Disconnect from the WhatsApp network.
     */
    public void disconnect() {
        f.channel().disconnect();
    }

    /**
     * Drain the message queue for application processing.
     *
     * @return List<ProtocolNode>
     * Return the message queue list.
     */
//    public List<ProtocolNode> getMessages() {
//        List<ProtocolNode> ret = messageQueue;
//        messageQueue = new LinkedList<ProtocolNode>();
//        return ret;
//    }

    /**
     * Log into the Whatsapp server.
     * <p>
     * ###Warning### using this method will generate a new password
     * from the WhatsApp servers each time.
     * <p>
     * If you know your password and wish to use it without generating
     * a new password - use the loginWithPassword() method instead.
     *
     * @throws WhatsAppException
     */
    public void login(boolean profileSubscribe) throws WhatsAppException {
        //TODO implement this
        throw new WhatsAppException("Not yet implemented");

    }

    /**
     * Login to the Whatsapp server with your password
     * <p>
     * If you already know your password you can log into the Whatsapp server
     * using this method.
     */
    public void loginWithPassword(String password) throws WhatsAppException {
        this.password = password;
        login();
    }

    private void login() throws WhatsAppException {
        try {
            doLogin();
//            if (loginStatus != LoginStatus.CONNECTED_STATUS) {
//                throw new WhatsAppException("Failed to log in");
//            }
        } catch (Exception e) {
            //TODO ver que pasa aca
            throw new WhatsAppException(e);
        }
    }

    public boolean isConnected() {
        return f.channel().isOpen() && loginStatus == LoginStatus.CONNECTED_STATUS;
    }

    public void reconnect() throws WhatsAppException {
        if (password == null) throw new WhatsAppException("No password exists");
        login();
    }

    /**
     * Send a request to get the current server properties
     *
     * @throws WhatsAppException
     */
    public void sendGetServerProperties() throws WhatsAppException {
        //TODO implement this
        throw new WhatsAppException("Not yet implemented");
    }


    public void sendPing() throws WhatsAppException {
        log.debug("Sending ping");

        String msgId = createMsgId("ping");
        ProtocolNode pingNode = new ProtocolNode("ping", null, null, null);

        Map<String, String> params = new HashMap<String, String>();
        params.put("id", msgId);
        params.put("xmlns", "w:p");
        params.put("type", "get");
        params.put("to", WHATSAPP_SERVER);

        ProtocolNode node = new ProtocolNode("iq", params, Arrays.asList(pingNode), null);
        sendNode(node);

    }


    private void preprocessProfilePicture(File filepath) {
        // TODO Auto-generated method stub
    }

    /**
     * Set the recovery token for your account to allow you to
     * retrieve your password at a later stage.
     *
     * @throws WhatsAppException
     */
    public void sendSetRecoveryToken(String token) throws WhatsAppException {
        //TODO implement this
        throw new WhatsAppException("Not yet implemented");
    }


    /**
     * Sets the bind of the new message.
     *
     * @throws WhatsAppException
     */
    public void setNewMessageBind(MessageProcessor processor) throws WhatsAppException {
        this.processor = processor;
    }

    /**
     * Upload file to WhatsApp servers.
     *
     * @return String
     * Return the remote url or null on failure.
     * @throws WhatsAppException
     */
    public String uploadFile(String file) throws WhatsAppException {
        //TODO implement this
        throw new WhatsAppException("Not yet implemented");
    }

    /**
     * Wait for message delivery notification.
     *
     * @throws WhatsAppException
     */
    public void waitForMessageReceipt() throws WhatsAppException {
        //TODO implement this
        throw new WhatsAppException("Not yet implemented");
    }

    /**
     * Check if account credentials are valid.
     * <p>
     * WARNING: WhatsApp now changes your password everytime you use this.
     * Make sure you update your config file if the output informs about
     * a password change.
     *
     * @return object
     * An object with server response.
     * - status: Account status.
     * - login: Phone number with country code.
     * - pw: Account password.
     * - type: Type of account.
     * - expiration: Expiration date in UNIX TimeStamp.
     * - kind: Kind of account.
     * - price: Formatted price of account.
     * - cost: Decimal amount of account.
     * - currency: Currency price of account.
     * - price_expiration: Price expiration in UNIX TimeStamp.
     * @throws JSONException
     * @throws WhatsAppException
     * @throws Exception
     */
    public boolean checkCredentials(String number) throws JSONException, WhatsAppException {
        Map<String, String> phone;
        if ((phone = dissectPhone()) == null) {
            throw new WhatsAppException("The prived phone number is not valid.");
        }

        // Build the url.
        String host = "https://" + WHATSAPP_CHECK_HOST;
        Map<String, String> query = new LinkedHashMap<String, String>();
        query.put("cc", phone.get("cc"));
        query.put("in", phone.get("phone"));
        query.put("id", identity);
        query.put("c", "cookie");

        JSONObject response = getResponse(host, query);
        log.debug(response.toString());
        if (!response.getString("status").equals("ok")) {
            throw new WhatsAppException("There was a problem trying to request the code. Status=" + response.getString("status"));
        } else {
            log.debug("Setting password: " + response.getString("pw"));
            password = response.getString("pw");
            return true;
        }
    }

    protected List<Country> getCountries() {
        return countries;
    }

    private List<Country> readCountries() throws WhatsAppException, IOException {
        Path path = Paths.get(this.getClass().getResource("/countries.csv").getPath());
        List<Country> countries = Files.lines(path).map(line -> new Country(line.split(","))).collect(Collectors.toList());
        log.debug("Loaded {} countries from {}", countries.size(), path.toString());
        return countries;
    }


    protected String buildIdentity(String id) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] hash = hash("SHA-1", id.getBytes());
        String hashString = new String(hash, "iso-8859-1");
        String newId = URLEncoder.encode(hashString, "iso-8859-1").toLowerCase();
        if (log.isDebugEnabled()) {
            log.debug("ID: " + newId);
        }
        return newId;
    }

    protected boolean checkIdentity(String id) throws UnsupportedEncodingException {

        if (id != null)
            return (URLDecoder.decode(id, "iso-8859-1").length() == 20);
        return false;
    }

    private void doLogin() throws InvalidKeyException, NoSuchAlgorithmException, IOException, InvalidKeySpecException, WhatsAppException, IncompleteMessageException, InvalidMessageException, InvalidTokenException, JSONException, EncodeException, DecodeException {
        encoder.getWriter().resetKey();
        decoder.getReader().resetKey();
        String resource = WHATSAPP_DEVICE + "-" + WHATSAPP_VER + "-" + PORT;
        byte[] data = encoder.getWriter().startStream(WHATSAPP_SERVER, resource);
        this.sendData(data);
        this.sendNode(createFeaturesNode(false));
        this.sendNode(createAuthNode());

//        if (challengeData != null) {
//
//            pollMessages();
//        }
//        if (loginStatus == LoginStatus.DISCONNECTED_STATUS) {
//            throw new WhatsAppException("Login failure");
//        }
//        int cnt = 0;
//        poller = new MessagePoller(this);
//        poller.start();
//        do {
//            try {
//                Thread.sleep(100);
//            } catch (InterruptedException e) {
//                throw new WhatsAppException(e);
//            }
//        } while ((cnt++ < 100) && (loginStatus == LoginStatus.DISCONNECTED_STATUS));
//        sendPresence("available");
    }

    /**
     * Add the auth response to protocoltreenode.
     *
     * @return ProtocolNode
     * Return itself.
     * @throws EncodeException
     * @throws IOException
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    private ProtocolNode createAuthResponseNode() throws EncodeException, IOException {
        byte[] resp = authenticate();
        Map<String, String> attributes = new LinkedHashMap<String, String>();
        //		attributes.put("xmlns","urn:ietf:params:xml:ns:xmpp-sasl");
        ProtocolNode node = new ProtocolNode("response", attributes, null, resp);

        return node;
    }

    /**
     * Authenticate with the Whatsapp Server.
     *
     * @return byte[]
     * Returns binary string
     * @throws EncodeException
     * @throws IOException
     */
    byte[] authenticate() throws EncodeException, IOException {
        List<byte[]> keys = generateKeys();
        inputKey = new KeyStream(keys.get(2), keys.get(3));
        outputKey = new KeyStream(keys.get(0), keys.get(1));

        ByteArrayOutputStream array = new ByteArrayOutputStream();
        array.write(phoneNumber.getBytes());
        array.write(challengeData);
        //		array.write(Long.toString((new Date()).getTime()/1000).getBytes());
        byte[] response = outputKey.encode(array.toByteArray(), 0, 0, array.size());
        return response;
    }

    List<byte[]> generateKeys() throws EncodeException {
        try {
            List<byte[]> keys = new LinkedList<byte[]>();
            for (int i = 0; i < 4; ++i) {
                ByteArrayOutputStream nonce = getChallengeData();
                nonce.write(i + 1);
                byte[] key = pbkdf2("SHA-1", base64_decode(password), nonce.toByteArray(), 2, 20, true);
                keys.add(key);
            }
            return keys;
        } catch (Exception e) {
            throw new EncodeException(e);
        }
    }

    private ByteArrayOutputStream getChallengeData() throws NoSuchAlgorithmException, IOException {
        if (challengeData == null) {
            log.info("Challenge data is missing!");
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            challengeData = new byte[20];
            sr.nextBytes(challengeData);
        }
        ByteArrayOutputStream os = new ByteArrayOutputStream(challengeData.length);
        os.write(challengeData);
        return os;
    }

    protected byte[] pbkdf2(String algo, byte[] password,
                            byte[] salt, int iterations, int length, boolean raw) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException {
        if (iterations <= 0 || length <= 0) {
            throw new InvalidKeySpecException("PBKDF2 ERROR: Invalid parameters.");
        }

        int hash_length = 20; //hash(algo, "", true).length();
        double block_count = Math.ceil(length / hash_length);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        for (int i = 1; i <= block_count; i++) {
            ByteArrayOutputStream last = new ByteArrayOutputStream();
            last.write(salt);
            ByteBuffer buffer = ByteBuffer.allocate(4);
            buffer.putInt(i);
            last.write(buffer.array());
            byte[] lastBuf = last.toByteArray();
            byte[] xorsum = KeyStream.hash_hmac(lastBuf, password);
            byte[] xorsum2 = xorsum;
            for (int j = 1; j < iterations; j++) {
                xorsum2 = KeyStream.hash_hmac(xorsum2, password);
                last.reset();
                int k = 0;
                for (byte b : xorsum) {
                    last.write(b ^ xorsum2[k++]);
                }
                xorsum = last.toByteArray();
            }
            output.write(xorsum);
        }
        if (raw) {
            return output.toByteArray();
        }
        return toHex(output.toByteArray()).getBytes();
    }

    public static String toHex(byte[] array) throws NoSuchAlgorithmException {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();
        if (paddingLength > 0) {
            return String.format("%0" + paddingLength + "d", 0) + hex;
        } else {
            return hex;
        }
    }

    byte[] base64_decode(String pwd) {
        return org.apache.commons.codec.binary.Base64.decodeBase64(pwd.getBytes());
    }


    /**
     * Will process the data from the server after it's been decrypted and parsed.
     * <p>
     * This also provides a convenient method to use to unit test the event framework.
     *
     * @throws IOException
     * @throws InvalidTokenException
     * @throws InvalidMessageException
     * @throws IncompleteMessageException
     * @throws WhatsAppException
     * @throws JSONException
     * @throws NoSuchAlgorithmException
     * @throws DecodeException
     * @throws InvalidKeyException
     */
    public void processInboundDataNode(ProtocolNode node) throws IncompleteMessageException, InvalidMessageException, InvalidTokenException, IOException, WhatsAppException, JSONException, NoSuchAlgorithmException, InvalidKeyException, DecodeException, EncodeException {
        ProtocolTag tag;
        try {
            tag = ProtocolTag.fromString(node.getTag());
            if (tag == null) {
                tag = ProtocolTag.UNKNOWN;
                log.info("Unknown/Unused tag (null) {}", node);
                //sendAck(node);
            }
        } catch (IllegalArgumentException e) {
            tag = ProtocolTag.UNKNOWN;
            log.info("Unknown/Unused tag " + node.getTag());
            log.info("Sending ack anywat to: {}", node);
        }

        switch (tag) {
            case CHALLENGE:
                processChallenge(node);
                break;
            case SUCCESS:
                loginStatus = LoginStatus.CONNECTED_STATUS;
                challengeData = node.getData();
                file_put_contents("nextChallenge.dat", challengeData);
                encoder.getWriter().setKey(outputKey);
                this.account().sendPresence("available");
                break;
            case FAILURE:
                log.error("Failure");
                break;
            case MESSAGE:
                processMessage(node);
                break;
            case ACK:
                processAck(node);
                break;
            case RECEIPT:
                processReceipt(node);
                break;
            case PRESENCE:
                processPresence(node);
                break;
            case IQ:
                processIq(node);
                break;
            case IB:
                processIb(node);
                break;
            case NOTIFICATION:
                processNotification(node);
                break;
            case CHATSTATE:
                processChatState(node);
                break;
            case STREAM_ERROR:
                throw new WhatsAppException("stream:error received: " + node);
            case PING:
                break;
            case QUERY:
                break;
            case START:
                break;
            case UNKNOWN:
                break;
            default:
                break;
        }
    }

    private void processChatState(ProtocolNode node) throws WhatsAppException {
        log.debug("Processing CHATSTATE");
        String from = parseJID(node.getAttribute("from"));
        String groupId = null;
        if (from.contains("-")) {
            groupId = from;
            from = parseJID(node.getAttribute("participant"));
        }
        if (node.hasChild("composing")) {
            Event event = new Event(EventType.MESSAGE_COMPOSING, phoneNumber);
            event.setGroupId(groupId);
            event.setFrom(from);
            eventManager.fireEvent(event);
        }
        if (node.hasChild("paused")) {
            Event event = new Event(EventType.MESSAGE_PAUSED, phoneNumber);
            event.setGroupId(groupId);
            event.setFrom(from);
            eventManager.fireEvent(event);
        }
    }

    private void processNotification(ProtocolNode node) throws WhatsAppException {
        String name = node.getAttribute("notify");
        String type = node.getAttribute("type");
        log.debug("Processing " + type + " NOTIFICATION: " + name);
        if (type.equals("status")) {

        }
        if (type.equals("picture")) {

        }
        if (type.equals("contacts")) {

        }
        if (type.equals("encrypt")) {

        }
        if (type.equals("w:gp2")) {
            List<ProtocolNode> groupList = node.getChild(0).getChildren();
            String groupId = parseJID(node.getAttribute("from"));

            if (node.hasChild("create")) {
                Event event = new Event(EventType.GROUP_CREATE, phoneNumber);
                event.setData(groupList);
                event.setGroupId(groupId);
                eventManager.fireEvent(event);
            }
            if (node.hasChild("add")) {
                Event event = new Event(EventType.GROUP_ADD, phoneNumber);
                event.setData(groupList);
                event.setGroupId(groupId);
                eventManager.fireEvent(event);
            }
            if (node.hasChild("remove")) {
                Event event = new Event(EventType.GROUP_REMOVE, phoneNumber);
                event.setData(groupList);
                event.setGroupId(groupId);
                eventManager.fireEvent(event);
            }
            if (node.hasChild("participant")) {

            }
            if (node.hasChild("subject")) {

            }

        }
        if (type.equals("account")) {

        }
        if (type.equals("features")) {

        }
        sendNotificationAck(node);
    }

//    private void addServerReceivedId(String receivedId) {
//        synchronized (serverReceivedId) {
//            serverReceivedId.add(receivedId);
//        }
//    }

    private void sendNotificationAck(ProtocolNode node) throws WhatsAppException {
        String from = node.getAttribute("from");
        String to = node.getAttribute("to");
        String participant = node.getAttribute("participant");
        String id = node.getAttribute("id");
        String type = node.getAttribute("type");

        Map<String, String> attributes = new HashMap<String, String>();
        if (to != null && !to.isEmpty())
            attributes.put("from", to);
        if (participant != null && !participant.isEmpty())
            attributes.put("participant", participant);
        attributes.put("to", from);
        attributes.put("class", "notification");
        attributes.put("id", id);
        attributes.put("type", type);

        ProtocolNode ack = new ProtocolNode("ack", attributes, null, null);

        sendNode(ack);
    }

    private void processReceipt(ProtocolNode node) throws WhatsAppException {
        log.debug("Processing RECEIPT");
        //addServerReceivedId(node.getAttribute("id"));
        eventManager.fireMessageReceivedClient(
                phoneNumber,
                node.getAttribute("from"),
                node.getAttribute("id"),
                (node.getAttribute("type") == null ? "" : node.getAttribute("type")),
                node.getAttribute("t")
        );

        sendAck(node, "receipt");
    }

    private void sendAck(ProtocolNode node, String clazz) throws WhatsAppException {
        Map<String, String> attributes = new HashMap<String, String>();

        attributes.put("to", node.getAttribute("from"));
        attributes.put("class", clazz);
        attributes.put("id", node.getAttribute("id"));
        Optional.ofNullable(node.getAttribute("type")).ifPresent(type -> attributes.put("type", type));
        ProtocolNode ack = new ProtocolNode("ack", attributes, null, null);
        sendNode(ack);
    }

    private void processAck(ProtocolNode node) {
        log.debug("Processing ACK");
        //addServerReceivedId(node.getAttribute("id"));
    }

    private void processIb(ProtocolNode node) throws IOException, WhatsAppException, IncompleteMessageException, InvalidMessageException, InvalidTokenException, JSONException, NoSuchAlgorithmException {
        String type = node.getAttribute("type");
        log.info("Processing IB " + (type == null ? "" : type));
        for (ProtocolNode n : node.getChildren()) {
            ProtocolTag tag = ProtocolTag.fromString(n.getTag());
            switch (tag) {
                case DIRTY:
                    List<String> categories = new LinkedList<String>();
                    categories.add(n.getAttribute("type"));
                    sendClearDirty(categories);
                    break;
                case OFFLINE:
                    log.info("Offline count" + n.getAttribute("count"));
                    break;
                default:
            }
        }
    }

    private void processIq(ProtocolNode node) throws IOException, WhatsAppException, IncompleteMessageException, InvalidMessageException, InvalidTokenException, JSONException, NoSuchAlgorithmException, InvalidKeyException, DecodeException {

        log.info("Processing IQ " + node.getAttribute("type"));
        ProtocolNode child = node.getChild(0);

        if (node.getAttribute("type").equals("get") && node.getAttribute("xmlns").equals("urn:xmpp:ping")) {
            eventManager.firePing(phoneNumber, node.getAttribute("id"));
            sendPong(node.getAttribute("id"));
        }
        if (node.getAttribute("type").equals("result")) {
            if (log.isDebugEnabled()) {
                log.debug("processIq: setting received id to " + node.getAttribute("id"));
            }
            //addServerReceivedId(node.getAttribute("id"));

            if (child != null) {
                if (child.getTag().equals(ProtocolTag.QUERY.toString())) {
                    if (child.getAttribute("xmlns").equals("jabber:iq:privacy")) {
                        // ToDo: We need to get explicitly list out the children as arguments
                        //       here.
                        eventManager.fireGetPrivacyBlockedList(
                                phoneNumber,
                                child.getChild(0).getChildren()
                        );
                    }
                    if (child.getAttribute("xmlns").equals("jabber:iq:last")) {
                        eventManager.fireGetRequestLastSeen(
                                phoneNumber,
                                node.getAttribute("from"),
                                node.getAttribute("id"),
                                child.getAttribute("seconds")
                        );
                    }
                }
                if (child.getTag().equals(ProtocolTag.SYNC.toString())) {
                    //sync result
                    ProtocolNode sync = child;
                    ProtocolNode existing = sync.getChild("in");
                    ProtocolNode nonexisting = sync.getChild("out");

                    //process existing first
                    Map<String, String> existingUsers = new HashMap<String, String>();
                    if (existing != null) {
                        for (ProtocolNode eChild : existing.getChildren()) {
                            existingUsers.put(new String(eChild.getData()), eChild.getAttribute("jid"));
                        }
                    }

                    //now process failed numbers
                    List<String> failedNumbers = new LinkedList<String>();
                    if (nonexisting != null) {
                        for (ProtocolNode neChild : nonexisting.getChildren()) {
                            failedNumbers.add(new String(neChild.getData()));
                        }
                    }

                    String index = sync.getAttribute("index");

                    SyncResult result = new SyncResult(index, sync.getAttribute("sid"), existingUsers, failedNumbers);
                    if (log.isDebugEnabled()) {
                        log.debug("Sync result: " + result.toString());
                    }
                    Event event = new Event(EventType.SYNC_RESULTS, phoneNumber);
                    event.setEventSpecificData(result);

                    eventManager.fireEvent(event);
                }
                //todo ver para que hacia esto, ni idea.
                //messageQueue.add(node);
            }
            if (child != null && child.getTag().equals("props")) {
                //server properties
                Map<String, String> props = new LinkedHashMap<String, String>();
                for (ProtocolNode c : child.getChildren()) {
                    props.put(c.getAttribute("name"), c.getAttribute("value"));
                }
                eventManager.fireGetServerProperties(
                        phoneNumber,
                        child.getAttribute("version"),
                        props
                );
            }
            if (child != null && child.getTag().equals("picture")) {
                eventManager.fireGetProfilePicture(
                        phoneNumber,
                        node.getAttribute("from"),
                        child.getAttribute("type"),
                        child.getData()
                );
            }
            if (child != null && child.getTag().equals("media")) {
                processUploadResponse(node);
            }
            if (child != null && child.getTag().equals("duplicate")) {
                processUploadResponse(node);
            }
            if (node.nodeIdContains("group")) {
                //There are multiple types of Group reponses. Also a valid group response can have NO children.
                //Events fired depend on text in the ID field.
                List<ProtocolNode> groupList = null;
                String groupId = null;
                if (child != null) {
                    groupList = child.getChildren();
                }
                if (node.nodeIdContains("creategroup")) {
                    groupId = child.getAttribute("id");
                    Event event = new Event(EventType.GROUP_CREATE, phoneNumber);
                    event.setData(groupList);
                    event.setGroupId(groupId);
                    eventManager.fireEvent(event);
                }
                if (node.nodeIdContains("endgroup")) {
                    groupId = child.getChild(0).getAttribute("id");
                    Event event = new Event(EventType.GROUP_END, phoneNumber);
                    event.setData(groupList);
                    event.setGroupId(groupId);
                    eventManager.fireEvent(event);
                }
                if (node.nodeIdContains("getgroups")) {
                    Event event = new Event(EventType.GET_GROUPS, phoneNumber);
                    event.setData(groupList);
                    eventManager.fireEvent(event);

                }
                if (node.nodeIdContains("getgroupinfo")) {
                    Event event = new Event(EventType.GET_GROUPINFO, phoneNumber);
                    event.setData(groupList);
                    eventManager.fireEvent(event);
                }
                if (node.nodeIdContains("getgroupparticipants")) {
                    groupId = parseJID(node.getAttribute("from"));
                    Event event = new Event(EventType.GET_GROUPS, phoneNumber);
                    event.setData(groupList);
                    event.setGroupId(groupId);
                    eventManager.fireEvent(event);
                }

            }

            if (node.getTag().equals("iq") && node.getAttribute("type").equals("error")) {
                //addServerReceivedId(node.getAttribute("id"));
            }
        }

    }

    public String getLastSendMsgId() {
        return this.lastSendMsgId;
    }

    /**
     * Process media upload response
     *
     * @return bool
     * @throws WhatsAppException
     * @throws InvalidTokenException
     * @throws InvalidMessageException
     * @throws IncompleteMessageException
     * @throws IOException
     * @throws JSONException
     * @throws NoSuchAlgorithmException
     * @throws DecodeException
     * @throws InvalidKeyException
     */
    //funcion mas o menos revisada.
    private boolean processUploadResponse(ProtocolNode node) throws IOException, IncompleteMessageException, InvalidMessageException, InvalidTokenException, WhatsAppException, JSONException, NoSuchAlgorithmException, InvalidKeyException, DecodeException {
        final String id = node.getAttribute("id");
        if (!mediaQueue.containsKey(id)) {
            log.warn("Message node id:{} not found in media queue for upload", id);
            eventManager.fireMediaUploadFailed(phoneNumber, id, node, null, "Message node not found in queue");
            return false;
        }

        final Map<String, Object> messageNode = mediaQueue.get(id);
        final MediaInfo mInfo = (MediaInfo) messageNode.get("mediaInfo");

        String url = null;
        String filesize = null;
        String filetype = null;
        String filename = null;
        String to = null;

        Optional<ProtocolNode> duplicate = Optional.ofNullable(node.getChild("duplicate"));

        if (duplicate.isPresent()) {
            url = duplicate.get().getAttribute("url");
            filesize = duplicate.get().getAttribute("size");
            filetype = duplicate.get().getAttribute("type");
            //todo revisar esto
            String[] exploded = url.split("/");
            filename = exploded[exploded.length - 1];
        } else {
            JSONObject json = WhatsMediaUploader.pushFile(node, messageNode, mInfo.getMediaFile(), phoneNumber);

            if (json == null) {
                eventManager.fireMediaUploadFailed(phoneNumber, id, node, messageNode, "Failed to push file to server");
                return false;
            }

            log.debug("Setting mediaInfo to: " + json.toString());

            url = json.getString("url");
            filesize = json.getString("size");
            filetype = json.getString("type");
            filename = json.getString("name");
        }

        final ProtocolNode mediaNode = new ProtocolNode("media");
        mediaNode.getAttributes().put("xmlns", "urn:xmpp:whatsapp:mms");
        mediaNode.getAttributes().put("type", filetype);
        mediaNode.getAttributes().put("url", url);
        mediaNode.getAttributes().put("encoding", "raw");
        mediaNode.getAttributes().put("file", filename);
        mediaNode.getAttributes().put("size", filesize);
        mediaNode.getAttributes().put("caption", mInfo.getCaption());

        to = ((List<String>) messageNode.get("to")).get(0);

        if (filetype.equals("image") || filetype.equals("video")) {
            mediaNode.setData(Files.readAllBytes(Paths.get(mInfo.getPreviewFile().toURI())));
        }

        /*
         * TODO support multiple recipients
		 */
        //        if (is_array($to)) {
        //            $this->sendBroadcast($to, $mediaNode);
        //        } else {
        //            $this->sendMessageNode($to, $mediaNode);
        //        }

        sendMessageNode(to, mediaNode, null);
        eventManager.fireMediaMessageSent(phoneNumber, to, id, filetype, url, filename, filesize, mediaNode.getData());
        return true;
    }

    private JSONObject createMediaInfo(ProtocolNode duplicate) {
        JSONObject info = new JSONObject();
        Map<String, String> attributes = duplicate.getAttributes();
        for (String key : attributes.keySet()) {
            try {
                info.put(key, attributes.get(key));
            } catch (JSONException e) {
                log.warn("Failed to add " + key + " to media info: " + e.getMessage());
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Created media info (for duplicate): " + info.toString());
        }
        return info;
    }

    private void sendPong(String msgid) throws IOException, WhatsAppException {
        Map<String, String> messageHash = new LinkedHashMap<String, String>();
        messageHash.put("to", WHATSAPP_SERVER);
        messageHash.put("id", msgid);
        messageHash.put("type", "result");

        ProtocolNode messageNode = new ProtocolNode("iq", messageHash, null, null);
        sendNode(messageNode);
        eventManager.fireSendPong(
                phoneNumber,
                msgid
        );
    }

    private void file_put_contents(String string, Object challengeData2) {
        // TODO Auto-generated method stub

    }

    private void processChallenge(ProtocolNode node) throws EncodeException, IOException, WhatsAppException {
        log.debug("processChallenge data length: " + node.getData().length);
        challengeData = node.getData();
        ProtocolNode dataNode = createAuthResponseNode();
        sendNode(dataNode);
        encoder.getWriter().setKey(outputKey);
        decoder.getReader().setKey(inputKey);
    }

    private void processPresence(ProtocolNode node) throws WhatsAppException {
        if (node.getAttribute("status") != null && node.getAttribute("status").equals("dirty")) {
            //clear dirty
            List<String> categories = new LinkedList<String>();
            if (node.getChildren() != null && node.getChildren().size() > 0) {
                for (ProtocolNode child : node.getChildren()) {
                    if (child.getTag().equals("category")) {
                        categories.add(child.getAttribute("name"));
                    }
                }
            }
            sendClearDirty(categories);
        }
        String from = node.getAttribute("from");
        String type = node.getAttribute("type");
        if (from != null && type != null) {
            if (from.startsWith(phoneNumber)
                    && !from.contains("-")) {
                eventManager.firePresence(
                        phoneNumber,
                        from,
                        type
                );
            }
            if (!from.startsWith(phoneNumber)
                    && from.contains("-")) {
            }
        }
    }

    private String parseJID(String attribute) {
        String[] parts = attribute.split("@");
        return parts[0];
    }

    private void sendClearDirty(List<String> categories) throws WhatsAppException {
        String msgId = createMsgId("cleardirty");

        List<ProtocolNode> catnodes = new LinkedList<ProtocolNode>();
        for (String category : categories) {
            Map<String, String> catmap = new HashMap<String, String>();
            catmap.put("type", category);
            ProtocolNode catnode = new ProtocolNode("clean", catmap, null, null);
            catnodes.add(catnode);
        }
        Map<String, String> nodemap = new HashMap<String, String>();
        nodemap.put("id", msgId);
        nodemap.put("type", "set");
        nodemap.put("to", WHATSAPP_SERVER);
        nodemap.put("xmlns", "urn:xmpp:whatsapp:dirty");
        ProtocolNode node = new ProtocolNode("iq", nodemap, catnodes, null);
        sendNode(node);
    }

    private void processMessage(ProtocolNode node) throws IOException, WhatsAppException {
        log.debug("processMessage:");
        //messageQueue.add(node);

        //do not send received confirmation if sender is yourself
        if (node.getAttribute("type").equals("text")) {
            sendMessageReceived(node, "read");
        }
        if (node.getAttribute("type").equals("media")) {
            processMediaMessage(node);
            sendMessageReceived(node, "read");
        }
        // check if it is a response to a status request
        String[] foo = node.getAttribute("from").split("@");
        if (foo.length > 1 && foo[1].equals("s.us") && node.getChild("body") != null) {
            eventManager.fireGetStatus(
                    phoneNumber,
                    node.getAttribute("from"),
                    node.getAttribute("type"),
                    node.getAttribute("id"),
                    node.getAttribute("t"),
                    node.getChild("body").getData()
            );
        }
        if (node.hasChild("x") && lastId.equals(node.getAttribute("id"))) {
            log.debug("VER ACA QUE ONDA< ES ESTE X");
            //sendNextMessage();
        }

        if (processor != null && (node.hasChild("body") || node.hasChild("media"))) {
            Message message = createMessage(node);
            processor.processMessage(message);
        }

        if (node.hasChild("notify") && node.getChild(0).getAttribute("name") != null &&
                node.getChild(0).getAttribute("name").length() < 1 && node.getChild("body") != null) {
            String author = node.getAttribute("author");
            if (author == null || author.length() < 1) {
                //private chat message
                eventManager.fireGetMessage(
                        phoneNumber,
                        node.getAttribute("from"),
                        node.getAttribute("id"),
                        node.getAttribute("type"),
                        node.getAttribute("t"),
                        node.getChild("notify").getAttribute("name"),
                        node.getChild("body").getData()
                );
            } else {
                //group chat message
                eventManager.fireGetGroupMessage(
                        phoneNumber,
                        node.getAttribute("from"),
                        author,
                        node.getAttribute("id"),
                        node.getAttribute("type"),
                        node.getAttribute("t"),
                        node.getChild("notify").getAttribute("name"),
                        node.getChild("body").getData()
                );
            }
        }
        if (node.hasChild("notification") && node.getChild("notification").getAttribute("type").equals("picture")) {
            if (node.getChild("notification").hasChild("set")) {
                eventManager.fireProfilePictureChanged(
                        phoneNumber,
                        node.getAttribute("from"),
                        node.getAttribute("id"),
                        node.getAttribute("t")
                );
            } else if (node.getChild("notification").hasChild("delete")) {
                eventManager.fireProfilePictureDeleted(
                        phoneNumber,
                        node.getAttribute("from"),
                        node.getAttribute("id"),
                        node.getAttribute("t")
                );
            }
        }
        if (node.getChild("notify") != null && node.getChild(0).getAttribute("name") != null && node.getChild("media") != null) {
            if (node.getChild(2).getAttribute("type") == "image") {
                eventManager.fireGetImage(
                        phoneNumber,
                        node.getAttribute("from"),
                        node.getAttribute("id"),
                        node.getAttribute("type"),
                        node.getAttribute("t"),
                        node.getChild(0).getAttribute("name"),
                        node.getChild(2).getAttribute("size"),
                        node.getChild(2).getAttribute("url"),
                        node.getChild(2).getAttribute("file"),
                        node.getChild(2).getAttribute("mimetype"),
                        node.getChild(2).getAttribute("filehash"),
                        node.getChild(2).getAttribute("width"),
                        node.getChild(2).getAttribute("height"),
                        node.getChild(2).getData()
                );
            }
            if (node.getChild(2).getAttribute("type") == "video") {
                eventManager.fireGetVideo(
                        phoneNumber,
                        node.getAttribute("from"),
                        node.getAttribute("id"),
                        node.getAttribute("type"),
                        node.getAttribute("t"),
                        node.getChild(0).getAttribute("name"),
                        node.getChild(2).getAttribute("url"),
                        node.getChild(2).getAttribute("file"),
                        node.getChild(2).getAttribute("size"),
                        node.getChild(2).getAttribute("mimetype"),
                        node.getChild(2).getAttribute("filehash"),
                        node.getChild(2).getAttribute("duration"),
                        node.getChild(2).getAttribute("vcodec"),
                        node.getChild(2).getAttribute("acodec"),
                        node.getChild(2).getData()
                );
            } else if (node.getChild(2).getAttribute("type") == "audio") {
                eventManager.fireGetAudio(
                        phoneNumber,
                        node.getAttribute("from"),
                        node.getAttribute("id"),
                        node.getAttribute("type"),
                        node.getAttribute("t"),
                        node.getChild(0).getAttribute("name"),
                        node.getChild(2).getAttribute("size"),
                        node.getChild(2).getAttribute("url"),
                        node.getChild(2).getAttribute("file"),
                        node.getChild(2).getAttribute("mimetype"),
                        node.getChild(2).getAttribute("filehash"),
                        node.getChild(2).getAttribute("duration"),
                        node.getChild(2).getAttribute("acodec")
                );
            }
            if (node.getChild(2).getAttribute("type") == "vcard") {
                eventManager.fireGetvCard(
                        phoneNumber,
                        node.getAttribute("from"),
                        node.getAttribute("id"),
                        node.getAttribute("type"),
                        node.getAttribute("t"),
                        node.getChild(0).getAttribute("name"),
                        node.getChild(2).getChild(0).getAttribute("name"),
                        node.getChild(2).getChild(0).getData()
                );
            }
            if (node.getChild(2).getAttribute("type") == "location") {
                String url = node.getChild(2).getAttribute("url");
                String name = node.getChild(2).getAttribute("name");
                eventManager.fireGetLocation(
                        phoneNumber,
                        node.getAttribute("from"),
                        node.getAttribute("id"),
                        node.getAttribute("type"),
                        node.getAttribute("t"),
                        node.getChild(0).getAttribute("name"),
                        name,
                        node.getChild(2).getAttribute("longitude"),
                        node.getChild(2).getAttribute("latitude"),
                        url,
                        node.getChild(2).getData()
                );
            }
        }
        if (node.getChild("x") != null) {
            if (log.isDebugEnabled()) {
                log.debug("processMessage: setting received id to " + node.getAttribute("id"));
            }
            //addServerReceivedId(node.getAttribute("id"));
            eventManager.fireMessageReceivedServer(
                    phoneNumber,
                    node.getAttribute("from"),
                    node.getAttribute("id"),
                    node.getAttribute("type"),
                    node.getAttribute("t")
            );
        }
        if (node.getChild("received") != null) {
            eventManager.fireMessageReceivedClient(
                    phoneNumber,
                    node.getAttribute("from"),
                    node.getAttribute("id"),
                    node.getAttribute("type"),
                    node.getAttribute("t")
            );
        }
        if (node.getAttribute("type").equals("subject")) {
            log.debug(node.toString());
            String[] reset_from = node.getAttribute("from").split("@");
            String[] reset_author = node.getAttribute("author").split("@");
            eventManager.fireGetGroupsSubject(
                    phoneNumber,
                    reset_from,
                    node.getAttribute("t"),
                    reset_author,
                    reset_author,
                    node.getChild(0).getAttribute("name"),
                    node.getChild(2).getData()
            );
        }

        this.text().sendMessageRead(node.getAttribute("from"),node.getAttribute("id"));

    }

    private Message createMessage(ProtocolNode message) {

        String from = parseJID(message.getAttribute("from"));
        String contentType = message.getAttribute("type");
        String participant = message.getAttribute("participant");
        String group = null;
        if (participant != null && !participant.isEmpty()) {
            group = from;
            from = parseJID(participant);
        }
        if (contentType.equals("text")) {
            ProtocolNode body = message.getChild("body");
            String hex = new String(body.getData());
            TextMessage text = new TextMessage(message, from, group);
            text.setText(hex);
            return text;
        }
        if (contentType.equals("media")) {
            ProtocolNode media = message.getChild("media");
            String type = media.getAttribute("type");
            if (type.equals("location")) {
                LocationMessage msg = new LocationMessage(message, from, group);
                msg.setLongitude(media.getAttribute("longitude"));
                msg.setLatitude(media.getAttribute("latitude"));
            } else if (type.equals("image")) {
                ImageMessage msg = new ImageMessage(message, from, group);
                String caption = media.getAttribute("caption");

                if (caption == null)
                    caption = "";
                msg.setCaption(caption);
                byte[] preview = media.getData();
                msg.setPreview(preview);
                msg.setContent(media.getAttribute("url"));
                return msg;
            } else if (type.equals("video")) {
                VideoMessage msg = new VideoMessage(message, from, group);
                String caption = media.getAttribute("caption");

                if (caption == null)
                    caption = "";
                msg.setCaption(caption);
                byte[] preview = media.getData();
                msg.setPreview(preview);
                msg.setContent(media.getAttribute("url"));
                return msg;
            } else if (type.equals("audio")) {
                AudioMessage msg = new AudioMessage(message, from, group);
                String caption = media.getAttribute("caption");

                if (caption == null)
                    caption = "";
                msg.setCaption(caption);
                msg.setContent(media.getAttribute("url"));
                msg.setAbitrate(media.getAttribute("abitrate"));
                msg.setAcodec(media.getAttribute("acodec"));
                msg.setAsampfreq(media.getAttribute("asampfreq"));
                msg.setDuration(media.getAttribute("duration"));
                msg.setFile(media.getAttribute("file"));
                msg.setFileHash(media.getAttribute("filehash"));
                msg.setIp(media.getAttribute("ip"));
                msg.setMimetype(media.getAttribute("mimetype"));
                msg.setOrigin(media.getAttribute("origin"));
                msg.setSeconds(media.getAttribute("seconds"));
                msg.setSize(media.getAttribute("size"));
                return msg;
            }

        }
        //TODO add specific classes for all supported messages
        log.info("Other message type found: " + message.toString());
        BasicMessage msg = new BasicMessage(MessageType.OTHER, message, from, group);
        return msg;
    }

    private void processMediaMessage(ProtocolNode node) throws WhatsAppException {
        // TODO Auto-generated method stub
        if (node.getChild(0).getAttribute("type").equals("image")) {
            String msgId = createMsgId("ack-media");

            Map<String, String> attributes = new HashMap<String, String>();
            attributes.put("url", node.getChild(0).getAttribute("url"));
            ProtocolNode ackNode = new ProtocolNode("ack", attributes, null, null);

            Map<String, String> iqAttributes = new HashMap<String, String>();
            iqAttributes.put("id", msgId);
            iqAttributes.put("xmlns", "w:m");
            iqAttributes.put("type", "set");
            iqAttributes.put("to", WHATSAPP_SERVER);
            List<ProtocolNode> nodeList = Lists.newLinkedList();
            nodeList.add(ackNode);
            ProtocolNode iqNode = new ProtocolNode("iq", iqAttributes, nodeList, null);

            sendNode(iqNode);
        }

    }

//    private void sendNextMessage() throws IOException, WhatsAppException {
//        if (outQueue.size() > 0) {
//            ProtocolNode msgnode = outQueue.remove(0);
//            msgnode.refreshTimes();
//            lastId = msgnode.getAttribute("id");
//            sendNode(msgnode);
//        } else {
//            lastId = null;
//        }
//    }

    private void sendMessageReceived(ProtocolNode msg, String type) throws IOException, WhatsAppException {
        Map<String, String> messageHash = new LinkedHashMap<String, String>();
        messageHash.put("to", msg.getAttribute("from"));
        if (type != null && type.equals("read"))
            messageHash.put("type", "type");

        messageHash.put("id", msg.getAttribute("id"));
        messageHash.put("t", Long.toString(new Date().getTime()));
        ProtocolNode messageNode = new ProtocolNode("receipt", messageHash, null, null);
        sendNode(messageNode);
        eventManager.fireSendMessageReceived(
                phoneNumber,
                msg.getAttribute("from"),
                messageHash.get("t")
        );
    }

    public void sendNode(ProtocolNode node) {
        f.channel().writeAndFlush(node);
    }

    private void sendData(byte[] data) throws IOException, WhatsAppException {
        ByteBuf buffer = f.channel().alloc().buffer(data.length);
        buffer.writeBytes(data);
        f.channel().writeAndFlush(buffer);
    }

    /**
     * Add the authentication nodes.
     *
     * @return ProtocolNode
     * Return itself.
     * @throws EncodeException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    private ProtocolNode createAuthNode() throws NoSuchAlgorithmException, EncodeException, IOException {
        Map<String, String> attributes = new LinkedHashMap<String, String>();
        //		attributes.put("xmlns", "urn:ietf:params:xml:ns:xmpp-sasl");
        attributes.put("mechanism", "WAUTH-2");
        attributes.put("user", phoneNumber);
        byte[] data = createAuthBlob();
        ProtocolNode node = new ProtocolNode("auth", attributes, null, data);
        return node;
    }


    private byte[] createAuthBlob() throws EncodeException, IOException, NoSuchAlgorithmException {
        if (challengeData == null) return null;
        // TODO
        //			byte[] key = pbkdf2("PBKDF2WithHmacSHA1", base64_decode(password), challengeData, 16, 20, true);
        List<byte[]> keys = generateKeys();
        inputKey = new KeyStream(keys.get(2), keys.get(3));
        outputKey = new KeyStream(keys.get(0), keys.get(1));
        decoder.getReader().setKey(inputKey);
        Map<String, String> phone = dissectPhone();
        ByteArrayOutputStream array = new ByteArrayOutputStream();
        array.write(phoneNumber.getBytes());
        array.write(challengeData);
        array.write(time().getBytes());
        array.write(WHATSAPP_USER_AGENT.getBytes());
        array.write(" MccMnc/".getBytes());
        array.write(phone.get("mcc").getBytes());
        array.write("001".getBytes());
        log.debug("createAuthBlog: challengeData=" + toHex(challengeData));
        log.debug("createAuthBlog: array=" + toHex(array.toByteArray()));
        challengeData = null;
        return outputKey.encode(array.toByteArray(), 0, 4, array.size() - 4);
    }

    /**
     * Dissect country code from phone number.
     *
     * @return map
     * An associative map with country code and phone number.
     * - country: The detected country name.
     * - cc: The detected country code (phone prefix).
     * - phone: The phone number.
     * - ISO3166: 2-Letter country code
     * - ISO639: 2-Letter language code
     * Return null if country code is not found.
     */
    private Map<String, String> dissectPhone() {
        return countries.stream()
                .filter(c -> phoneNumber.startsWith(c.getCountryCode()))
                .findFirst()
                .map(c -> {
                    Map<String, String> ret = Maps.newHashMap();
                    ret.put("country", c.getName());
                    ret.put("cc", c.getCountryCode());
                    ret.put("phone", phoneNumber.substring(c.getCountryCode().length()));
                    ret.put("mcc", c.getMcc());
                    ret.put("ISO3166", c.getIso3166());
                    ret.put("ISO639", c.getIso639());
                    return ret;
                }).orElse(null);
    }


    public String time() {
        Date now = new Date();
        return Long.toString(now.getTime() / 1000);
    }

    /**
     * Add stream features.
     *
     * @return ProtocolNode
     * Return itself.
     */
    private ProtocolNode createFeaturesNode(boolean profileSubscribe) {
        LinkedList<ProtocolNode> nodes = new LinkedList<ProtocolNode>();
        ProtocolNode node = new ProtocolNode("readreceipts", null, null, null);
        nodes.add(node);
        if (profileSubscribe) {
            Map<String, String> attributes = new LinkedHashMap<String, String>();
            attributes.put("type", "all");
            ProtocolNode profile = new ProtocolNode("w:profile:picture", attributes, null, null);
            nodes.add(profile);
        }
        node = new ProtocolNode("privacy", null, null, null);
        nodes.add(node);
        node = new ProtocolNode("presence", null, null, null);
        nodes.add(node);
        node = new ProtocolNode("groups_v2", null, null, null);
        nodes.add(node);
        ProtocolNode parent = new ProtocolNode("stream:features", null, nodes, null);

        return parent;
    }


    private JSONObject getResponse(String host, Map<String, String> query) throws JSONException {
        Client client = ClientBuilder.newClient();

        StringBuilder url = new StringBuilder();
        url.append(host);
        String delimiter = "?";
        for (String key : query.keySet()) {
            url.append(delimiter);
            url.append(key);
            url.append("=");
            url.append(query.get(key));
            delimiter = "&";
        }
        if (log.isDebugEnabled()) {
            log.debug("Request: " + url.toString());
        }
        WebTarget target = client.target(url.toString());
        String resp = target.request(MediaType.APPLICATION_JSON).header("User-Agent", WHATSAPP_USER_AGENT).get(String.class);
        return new JSONObject(resp);
    }


    /**
     * Send node to the servers.
     *
     * @param to   The recipient to send.
     * @param node The node that contains the message.
     * @return message id
     * @throws IOException
     * @throws InvalidTokenException
     * @throws InvalidMessageException
     * @throws IncompleteMessageException
     * @throws WhatsAppException
     * @throws JSONException
     * @throws NoSuchAlgorithmException
     * @throws DecodeException
     * @throws InvalidKeyException
     */
    private String sendMessageNode(String to, ProtocolNode node, String id) throws IOException, IncompleteMessageException, InvalidMessageException, InvalidTokenException, WhatsAppException, JSONException, NoSuchAlgorithmException, InvalidKeyException, DecodeException {
        Map<String, String> messageHash = new LinkedHashMap<String, String>();
        messageHash.put("to", WhatsUtils.getJID(to));
        if (node.getTag().equals("body")) {
            messageHash.put("type", "text");
        } else {
            messageHash.put("type", "media");
        }
        messageHash.put("id", (id == null ? createMsgId("message") : id));
        messageHash.put("t", time());

        List<ProtocolNode> list = new LinkedList<ProtocolNode>();
        list.add(node);
        ProtocolNode messageNode = new ProtocolNode("message", messageHash, list, null);
        sendNode(messageNode);
        eventManager.fireSendMessage(
                phoneNumber,
                WhatsUtils.getJID(to),
                messageHash.get("id"),
                node
        );
        return lastSendMsgId = messageHash.get("id");
    }

    public String createMsgId(String prefix) {
        return String.format("%s-%s-%s", prefix, time(), messageCounter.getAndIncrement());
    }

    public String getIdentity() {
        return identity;
    }

    public void setIdentity(String identity) {
        this.identity = identity;
    }

    public String getName() {
        return name;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public EventManager getEventManager() {
        return eventManager;
    }

    public void setEventManager(EventManager eventManager) {
        this.eventManager = eventManager;
    }

    public void setChallengeData(String challenge) {
        challengeData = BinHex.hex2bin(challenge);
    }

    public void setPassword(String pw) {
        this.password = pw;
    }

    public KeyStream getInputKey() {
        return inputKey;
    }

    public void setInputKey(KeyStream inputKey) {
        this.inputKey = inputKey;
    }

    public KeyStream getOutputKey() {
        return outputKey;
    }
}