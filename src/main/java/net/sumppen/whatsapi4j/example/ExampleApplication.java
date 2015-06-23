package net.sumppen.whatsapi4j.example;

import net.sumppen.whatsapi4j.*;
import org.json.JSONException;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Example application
 * Launch with: java -cp target/dependency/*:target/whatsapi4j-1.0.0-SNAPSHOT.jar net.sumppen.whatsapi4j.example.ExampleApplication 358401122333 'mypassword' 'mytestapplication' 'My Test Account'
 *
 * @author kim
 */
public class ExampleApplication {
    public static boolean running = true;
    private static final String RELEASE_TOKEN_CONST = "PdA2DJyKoUrwLw1Bg6EIhzh502dF9noR9uFCllGk";
    private static final String RELEASE_TIME = "1419900749520";
    private static final int PORT = 443;                                      // The port of the WhatsApp server.
    private final int TIMEOUT_SEC = 2;                                  // The timeout for the connection with the WhatsApp servers.
    private final String WHATSAPP_CHECK_HOST = "v.whatsapp.net/v2/exist";  // The check credentials host.
    public static final String WHATSAPP_GROUP_SERVER = "g.us";                   // The Group server hostname
    private final String WHATSAPP_HOST = "c.whatsapp.net";                 // The hostname of the WhatsApp server.
    private final String WHATSAPP_REGISTER_HOST = "v.whatsapp.net/v2/register"; // The register code host.
    private final String WHATSAPP_REQUEST_HOST = "v.whatsapp.net/v2/code";      // The request code host.
    public static final String WHATSAPP_SERVER = "s.whatsapp.net";               // The hostname used to login/send messages.
    private static final String WHATSAPP_DEVICE = "S40";                      // The device name.
    private static final String WHATSAPP_VER = "2.12.81";                // The WhatsApp version.
    private final String WHATSAPP_USER_AGENT = "WhatsApp/2.12.81 S40Version/14.26 Device/Nokia302";// User agent used in request/registration code.
    private final String WHATSAPP_VER_CHECKER = "https://coderus.openrepos.net/whitesoft/whatsapp_version"; // Check WhatsApp version


    private enum WhatsAppCommand {
        send, request, register, status, text, sendText, image, sendImage, video, sendVideo, groups, sync, help, exit
    }


    public static void main(String[] args) throws WhatsAppException, IOException, NoSuchAlgorithmException, InterruptedException, EncodeException, InvalidKeyException, IncompleteMessageException, InvalidTokenException, JSONException, DecodeException, InvalidMessageException, InvalidKeySpecException {
        String username = "5491169108537";
        String password = "A9DHQXAFJkl1oPQUVS+K32CkzOQ=";
        String identity = "wtv";
        String nickname = "wtv";

//        String filename = "/tmp/exampleapplication.log";
//        System.setProperty("org.slf4j.simpleLogger.logFile", filename);
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "debug");
        System.setProperty("org.slf4j.simpleLogger.showDateTime", "true");

        WhatsApi wa = new WhatsApi(username, identity, nickname);
        wa.connect();
        wa.loginWithPassword(password);


        System.in.read();
        System.out.println("ME FUIIIIIIIIII");


//        Environment.initializeIfEmpty();
//        TcpClient<Buffer, Buffer> client = NetStreams.tcpClient("c.whatsapp.net", 443);
//        String resource = ExampleApplication.WHATSAPP_DEVICE + "-" + ExampleApplication.WHATSAPP_VER + "-" + ExampleApplication.PORT;
//       //este putillo mantiene la data hasta que se puede procesar
//        RingBufferProcessor<Buffer> stream = RingBufferProcessor.create();
//        BinTreeNodeWriter writer = new BinTreeNodeWriter();
//
//       boolean connected = client.start(conn -> {
//            conn.log("conn").consume(System.out::println);
//            //ni idea porque el wrap, pero bueno funciona asi. capcaity 1 para que los mande al toque
//            return conn.writeBufferWith(Streams.wrap(stream).capacity(1));
//        }).awaitSuccess(10, TimeUnit.SECONDS);
//
//        writer.resetKey();
//        byte[] data = writer.startStream(WHATSAPP_SERVER, resource);
//
//        stream.onNext(Buffer.wrap(data));
//        stream.onNext(Buffer.wrap(data));
//        stream.onNext(Buffer.wrap(data));
////
//////        ProtocolNode feat = createFeaturesNode(false);
////        ProtocolNode auth = createAuthNode();
//
//        Thread.sleep(2000);
//
//        stream.onNext(Buffer.wrap(data));
//        stream.onNext(Buffer.wrap(data));
//
//

    }


//        boolean loggedIn = false;

//
//        String username = "5491163977272";
//        String password = "79dL0X3Rx2oA8FfMc01yfHBEzlo=";
//        String identity = "mytestapplication";
//        String nickname = "Guardia";
//
//        WhatsApi wa = null;
//        try {
//            wa = new WhatsApi(username, identity, nickname);
//
//            EventManager eventManager = new ExampleEventManager();
//            wa.setEventManager(eventManager);
//            MessageProcessor mp = new ExampleMessageProcessor();
//            wa.setNewMessageBind(mp);
//            if (!wa.connect()) {
//                System.out.println("Failed to connect to WhatsApp");
//                System.exit(1);
//            }
//            if (password != null) {
//                wa.loginWithPassword(password);
//                loggedIn = true;
//            }
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
}



