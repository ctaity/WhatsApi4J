package net.sumppen.whatsapi4j.operation;

import net.sumppen.whatsapi4j.ProtocolNode;
import net.sumppen.whatsapi4j.WhatsApi;
import net.sumppen.whatsapi4j.WhatsAppException;

import java.util.List;

/**
 * Created by taity on 6/20/15.
 */
public class GroupOps extends BaseOps {

    public GroupOps(WhatsApi api) {
        super(api);
    }

    /**
     * Send a request to return a list of groups user is currently participating
     * in.
     * <p>
     * To capture this list you will need to bind the "onGetGroups" event.
     *
     * @throws WhatsAppException
     */
    public void getGroups() throws WhatsAppException {
        ProtocolNode child = new ProtocolNode("participating");
        child.getAttributes().put("id", createMsgId("getgroups"));
        child.getAttributes().put("type", "get");
        child.getAttributes().put("xmlns", "w:g2");
        child.getAttributes().put("to", WhatsApi.WHATSAPP_GROUP_SERVER);

        ProtocolNode node = new ProtocolNode("iq");
        node.getChildren().add(child);

        sendNode(node);
//        try {
//            waitForServer(msgID);
//        } catch (Exception e) {
//            throw new WhatsAppException("Error getting groups", e);
//        }
    }

    public void sendGetGroupsInfo(String gjid) throws WhatsAppException {
        //TODO implement this
        throw new WhatsAppException("Not yet implemented");
    }

    /**
     * Send a request to get information about a specific group
     *
     * @throws WhatsAppException
     */
    public void sendGetGroupsOwning() throws WhatsAppException {
        //TODO implement this
        throw new WhatsAppException("Not yet implemented");
    }

    /**
     * Send a request to return a list of groups user has started
     * in.
     * <p>
     * To capture this list you will need to bind the "onGetGroups" event.
     *
     * @throws WhatsAppException
     */
    public void sendGetPrivacyBlockedList() throws WhatsAppException {
        //TODO implement this
        throw new WhatsAppException("Not yet implemented");
    }

    /**
     * Create a group chat.
     *
     * @return String
     * The group ID.
     * @throws WhatsAppException
     */
    public String sendGroupsChatCreate(String subject, List<String> participants) throws WhatsAppException {
        //TODO implement this
        throw new WhatsAppException("Not yet implemented");
    }

    /**
     * End or delete a group chat
     *
     * @throws WhatsAppException
     */
    public void sendGroupsChatEnd(String gjid) throws WhatsAppException {
        //TODO implement this
        throw new WhatsAppException("Not yet implemented");
    }

    /**
     * Leave a group chat
     *
     * @throws WhatsAppException
     */
    public void sendGroupsLeave(List<String> gjids) throws WhatsAppException {
        ProtocolNode leave = new ProtocolNode("leave");
        leave.getAttributes().put("action", "delete");

        gjids.stream().map(gjid -> {
            ProtocolNode node = new ProtocolNode("group");
            node.getAttributes().put("id", getJID(gjid));
            return node;
        }).forEach(leave.getChildren()::add);

        ProtocolNode node = new ProtocolNode("iq");
        node.getAttributes().put("id", createMsgId("leavegroups"));
        node.getAttributes().put("to", WhatsApi.WHATSAPP_GROUP_SERVER);
        node.getAttributes().put("type", "set");
        node.getAttributes().put("xmlns", "w:g2");
        node.getChildren().add(leave);
        sendNode(node);
    }


    /**
     * Add participant(s) to a group.
     *
     * @throws WhatsAppException
     */
    public void sendGroupsParticipantsAdd(String groupId, List<String> participants) throws WhatsAppException {
        //TODO implement this
        throw new WhatsAppException("Not yet implemented");
    }

    /**
     * Remove participant(s) from a group.
     *
     * @throws WhatsAppException
     */
    public void sendGroupsParticipantsRemove(String groupId, List<String> participants) throws WhatsAppException {
        //TODO implement this
        throw new WhatsAppException("Not yet implemented");
    }

    /**
     * Set the picture for the group
     *
     * @throws WhatsAppException
     */
    public void sendSetGroupPicture(String gjid, String path) throws WhatsAppException {
        //TODO implement this
        throw new WhatsAppException("Not yet implemented");
    }

}
