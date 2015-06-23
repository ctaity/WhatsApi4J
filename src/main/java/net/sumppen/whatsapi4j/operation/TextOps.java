package net.sumppen.whatsapi4j.operation;

import net.sumppen.whatsapi4j.ProtocolNode;
import net.sumppen.whatsapi4j.WhatsApi;
import net.sumppen.whatsapi4j.WhatsAppException;
import net.sumppen.whatsapi4j.tools.CharsetUtils;

/**
 * Created by taity on 6/20/15.
 */
public class TextOps extends BaseOps {

    public TextOps(WhatsApi api) {
        super(api);
    }

    /**
     * Send a text message to the user/group.
     *
     * @return String
     */
    public void sendMessage(String to, String message) throws WhatsAppException {
        sendMessage(to, message, null);
    }

    /**
     * Send a text message to the user/group.
     *
     * @return String
     */
    public void sendMessage(String to, String message, String id) throws WhatsAppException {
        message = parseMessageForEmojis(message);
        ProtocolNode messageNode = this.createMessageNode(to, new ProtocolNode("body", null, null, CharsetUtils.toBytes(message)));
        messageNode.getAttributes().put("type", "text");
        this.sendNode(messageNode);
    }

    /**
     * Parse the message text for emojis
     * <p>
     * This will look for special strings in the message text
     * that need to be replaced with a unicode character to show
     * the corresponding emoji.
     * <p>
     * Emojis should be entered in the message text either as the
     * correct unicode character directly, or if this isn't possible,
     * by putting a placeholder of ##unicodeNumber## in the message text.
     * Include the surrounding ##
     * eg:
     * ##1f604## this will show the smiling face
     * ##1f1ec_1f1e7## this will show the UK flag.
     * <p>
     * Notice that if 2 unicode characters are required they should be joined
     * with an underscore.
     *
     * @return string
     */
    private String parseMessageForEmojis(String txt) {
        // TODO Auto-generated method stub
        return txt;
    }


}
