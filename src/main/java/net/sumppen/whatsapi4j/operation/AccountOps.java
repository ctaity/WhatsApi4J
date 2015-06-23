package net.sumppen.whatsapi4j.operation;

import net.sumppen.whatsapi4j.ProtocolNode;
import net.sumppen.whatsapi4j.SyncType;
import net.sumppen.whatsapi4j.WhatsApi;
import net.sumppen.whatsapi4j.WhatsAppException;
import net.sumppen.whatsapi4j.tools.CharsetUtils;
import org.apache.commons.lang3.Validate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

/**
 * Created by taity on 6/20/15.
 */
public class AccountOps extends BaseOps {
    private final static Logger log = LoggerFactory.getLogger(AccountOps.class);

    public AccountOps(WhatsApi api) {
        super(api);
    }

    /**
     * Send the active status. User will show up as "Online" (as long as socket is connected).
     *
     * @throws net.sumppen.whatsapi4j.WhatsAppException
     */
    public void sendActiveStatus() throws WhatsAppException {
        ProtocolNode messageNode = new ProtocolNode("presence");
        messageNode.getAttributes().put("type", "active");
        sendNode(messageNode);
    }


    public void sendClientConfig() throws WhatsAppException {
        //TODO implement this
        throw new WhatsAppException("Not yet implemented");
    }

    public void sendGetClientConfig() throws WhatsAppException {
        //TODO implement this
        throw new WhatsAppException("Not yet implemented");
    }

    /**
     * Send a request to get a list of people you have currently blocked
     *
     * @throws WhatsAppException
     */
    public void sendGetPrivacyBlockedList() throws WhatsAppException {
        //TODO implement this
        throw new WhatsAppException("Not yet implemented");
    }


    public void sendGetProfilePicture(String number) throws WhatsAppException {
        sendGetProfilePicture(number, false);
    }

    /**
     * Send presence subscription, automatically receive presence updates as long as the socket is open.
     *
     * @throws WhatsAppException
     */
    public void sendPresenceSubscription(String to) throws WhatsAppException {
        //TODO implement this
        throw new WhatsAppException("Not yet implemented");
    }


    /**
     * Set the list of numbers you wish to block receiving from.
     *
     * @throws WhatsAppException
     */
    public void sendSetPrivacyBlockedList(List<String> blockedJids) throws WhatsAppException {
        //TODO implement this
        throw new WhatsAppException("Not yet implemented");
    }

    /**
     * Set your profile picture. Thumbnail should be 96px size version of image
     *
     * @throws WhatsAppException
     */
    public void sendSetProfilePicture(File image, File thumbnail) throws WhatsAppException, IOException {
        sendSetPicture(api.getPhoneNumber(), image, thumbnail);
    }

    public String sendSync(List<String> numbers, List<String> deletedNumbers, SyncType syncType, int index, boolean last) throws WhatsAppException {
        List<ProtocolNode> users = new LinkedList<ProtocolNode>();

        for (String number : numbers) {
            // number must start with '+' if international contact
            if (number.length() > 1) {
                if (!number.startsWith("+")) {
                    number = "+" + number;
                }
                ProtocolNode user = new ProtocolNode("user", null, null, number.getBytes());
                users.add(user);
            }
        }

        if (deletedNumbers != null && deletedNumbers.size() > 0) {
            for (String number : deletedNumbers) {
                Map<String, String> map = new HashMap<String, String>();
                map.put("jid", getJID(number));
                map.put("type", "delete");
                ProtocolNode user = new ProtocolNode("user", map, null, null);
                users.add(user);
            }
        }

        String mode = null;
        String context = null;
        switch (syncType) {
            case FULL_REGISTRATION:
                mode = "full";
                context = "registration";
                break;
            case FULL_INTERACTIVE:
                mode = "full";
                context = "interactive";
                break;
            case FULL_BACKGROUND:
                mode = "full";
                context = "background";
                break;
            case DELTA_INTERACTIVE:
                mode = "delta";
                context = "interactive";
                break;
            case DELTA_BACKGROUND:
                mode = "delta";
                context = "background";
                break;
            case QUERY_INTERACTIVE:
                mode = "query";
                context = "interactive";
                break;
            case CHUNKED_REGISTRATION:
                mode = "chunked";
                context = "registration";
                break;
            case CHUNKED_INTERACTIVE:
                mode = "chunked";
                context = "interactive";
                break;
            case CHUNKED_BACKGROUND:
                mode = "chunked";
                context = "background";
                break;
            default:
                mode = "delta";
                context = "background";
        }

        String id = createMsgId("sendsync_");
        Date now = new Date();
        long longSid = ((now.getTime() + 11644477200L) * 10000);
        String sid = Long.toString(longSid);

        Map<String, String> syncMap = new HashMap<String, String>();
        syncMap.put("mode", mode);
        syncMap.put("context", context);
        syncMap.put("sid", sid);
        syncMap.put("index", "" + index);
        syncMap.put("last", (last ? "true" : "false"));

        ProtocolNode syncNode = new ProtocolNode("sync",
                syncMap, users, null);

        Map<String, String> nodeMap = new HashMap<String, String>();
        nodeMap.put("id", id);
        nodeMap.put("xmlns", "urn:xmpp:whatsapp:sync");
        nodeMap.put("type", "get");

        List<ProtocolNode> nodeList = new LinkedList<ProtocolNode>();
        nodeList.add(syncNode);

        ProtocolNode node = new ProtocolNode("iq", nodeMap, nodeList, null);

        sendNode(node);

        return id;
    }


    /**
     * Set your profile picture
     *
     * @throws WhatsAppException
     */
    //todo hacer las alternativas depues con byte , etc
    private void sendSetPicture(String jid, File image, File thumbnail) throws WhatsAppException, IOException {
        Validate.isTrue(image.isFile());
        Validate.isTrue(image.canRead());
        Validate.isTrue(image.length() > 0);
        Validate.isTrue(thumbnail.isFile());
        Validate.isTrue(thumbnail.canRead());
        Validate.isTrue(thumbnail.length() > 0);

        ProtocolNode picture = new ProtocolNode("picture");
        picture.setData(Files.readAllBytes(Paths.get(image.toURI())));

        ProtocolNode thumb = new ProtocolNode("picture");
        thumb.getAttributes().put("type", "preview");
        thumb.setData(Files.readAllBytes(Paths.get(thumbnail.toURI())));

        ProtocolNode node = new ProtocolNode("iq");
        node.getChildren().add(thumb);
        node.getChildren().add(picture);
        node.getAttributes().put("id", createMsgId("setphoto"));
        node.getAttributes().put("to", getJID(jid));
        node.getAttributes().put("type", "set");
        node.getAttributes().put("xmlns", "w:profile:picture");

        sendNode(node);
    }


    /**
     * Get profile picture of specified user
     *
     * @throws WhatsAppException
     */
    public void sendGetProfilePicture(String number, boolean large) throws WhatsAppException {
        Map<String, String> map = new LinkedHashMap<String, String>();
        map.put("type", large ? "image" : "preview");
        ProtocolNode picture = new ProtocolNode("picture", map, null, null);

        map = new LinkedHashMap<String, String>();
        map.put("id", createMsgId("getpicture"));
        map.put("type", "get");
        map.put("xmlns", "w:profile:picture");
        map.put("to", getJID(number));

        List<ProtocolNode> lista = new LinkedList<ProtocolNode>();
        lista.add(picture);

        ProtocolNode node = new ProtocolNode("iq", map, lista, null);
        try {
            sendNode(node);
            //waitForServer(map.get("id"));
        } catch (Exception e) {
            throw new WhatsAppException("Failed to get profile picture", e);
        }
    }

    /**
     * Request to retrieve the last online time of specific user.
     */
    public void sendGetRequestLastSeen(String to) {
        //TODO implement this
    }

    /**
     * Send the composing message status. When typing a message.
     *
     * @throws WhatsAppException
     */
    public void sendMessageComposing(String to) throws WhatsAppException {
        sendChatState(to, "composing");
    }

    /**
     * Send the 'paused composing message' status.
     *
     * @throws WhatsAppException
     */
    public void sendMessagePaused(String to) throws WhatsAppException {
        sendChatState(to, "paused");
    }


    private void sendChatState(String to, String state) {
        ProtocolNode messageNode = new ProtocolNode("chatstate");
        messageNode.getAttributes().put("to", getJID(to));
        messageNode.getChildren().add(new ProtocolNode(state));
        sendNode(messageNode);

    }

    /**
     * Update the user status.
     *
     * @throws WhatsAppException
     */
    public void sendStatusUpdate(String txt) throws WhatsAppException {
        ProtocolNode node = new ProtocolNode("iq");
        node.getAttributes().put("to", "s.whatsapp.net");
        node.getAttributes().put("type", "set");
        node.getAttributes().put("id", createMsgId("sendstatus"));
        node.getAttributes().put("xmlns", "status");

        ProtocolNode child = new ProtocolNode("status");
        child.setData(CharsetUtils.toBytes(txt));
        node.getChildren().add(child);

        try {
            sendNode(node);
            //eventManager.fireSendStatusUpdate(phoneNumber, txt);
        } catch (Exception e) {
            throw new WhatsAppException("Failed to update status");
        }
    }


    //por ahi cambiarlo a enum
    public void sendPresence(String type) throws IOException, WhatsAppException {
        //ANDA    <presence name="wtv"></presence>
        //NO ANDA <presence name="wtv"></presence>


        ProtocolNode node = new ProtocolNode("presence");
        node.getAttributes().put("name", api.getName());
        sendNode(node);

//        Map<String, String> presence = new LinkedHashMap<String, String>();
//        //		presence.put("type",type);
//        presence.put("name", api.getName());
//        ProtocolNode node = new ProtocolNode("presence", presence, null, null);
//        sendNode(node);
//       // eventManager.fireSendPresence(phoneNumber, type, presence.get("name"));
    }

}

