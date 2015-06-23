package net.sumppen.whatsapi4j.operation;

import com.google.common.collect.Lists;
import net.sumppen.whatsapi4j.ProtocolNode;
import net.sumppen.whatsapi4j.WhatsApi;
import net.sumppen.whatsapi4j.WhatsAppException;
import net.sumppen.whatsapi4j.WhatsUtils;
import org.apache.commons.lang3.Validate;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Created by taity on 6/20/15.
 */
public class BaseOps {
    protected WhatsApi api;

    public BaseOps(WhatsApi api) {
        Validate.notNull(api);
        this.api = api;
    }

    protected void sendNode(ProtocolNode node) {
        this.api.sendNode(node);
    }

    protected ProtocolNode createMessageNode(String to, ProtocolNode node) {
        return this.createMessageNode(to, node, null);
    }

    protected String createMsgId(String key) {
        return api.createMsgId("message");
    }

    protected String getJID(String key) {
        return WhatsUtils.getJID(key);
    }

    protected ProtocolNode createMessageNode(String to, ProtocolNode node, String id) {
        Map<String, String> messageHash = new LinkedHashMap<String, String>();
        messageHash.put("to", getJID(to));
//        if (node.getTag().equals("body")) {
//            messageHash.put("type", "text");
//        } else {
//            messageHash.put("type", "media");
//        }

        messageHash.put("id", Optional.ofNullable(id).orElse(this.createMsgId("message")));
        messageHash.put("t", api.time());

        List<ProtocolNode> list = Lists.newLinkedList();
        list.add(node);
        ProtocolNode messageNode = new ProtocolNode("message", messageHash, list, null);

        // sendNode(messageNode);
//        eventManager.fireSendMessage(
//                phoneNumber,
//                getJID(to),
//                messageHash.get("id"),
//                node
//        );
        return messageNode; //lastSendMsgId = messageHash.get("id");
    }

    public void sendMessageRead(String to, String id) throws WhatsAppException {
        ProtocolNode messageNode = new ProtocolNode("receipt");
        messageNode.getAttributes().put("type", "read");
        messageNode.getAttributes().put("to", getJID(to));
        messageNode.getAttributes().put("id", id);
        this.sendNode(messageNode);
    }
}
