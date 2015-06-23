package net.sumppen.whatsapi4j.operation;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import net.sumppen.whatsapi4j.*;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.Validate;
import org.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;

/**
 * Created by taity on 6/20/15.
 */
public class MediaOps extends BaseOps {
    private final static Logger log = LoggerFactory.getLogger(WhatsApi.class);

    private static final String[] AUDIO_EXTENSIONS = {"3gp", "caf", "wav", "mp3", "mp4", "wma", "ogg", "aif", "aac", "m4a"};
    private static final String[] IMAGE_EXTENSIONS = {"jpg", "jpeg", "gif", "png"};
    private static final String[] VIDEO_EXTENSIONS = {"3gp", "mp4", "mov", "avi"};

    private static final int AUDIO_MAXSIZE = 10 * 1024 * 1024;
    private static final int IMAGE_MAXSIZE = 5 * 1024 * 1024;
    private static final int VIDEO_MAXSIZE = 20 * 1024 * 1024;

    private static final String IMAGE_TYPE = "image";
    private static final String VIDEO_TYPE = "video";
    private static final String AUDIO_TYPE = "audio";

    private Map<String, Map<String, Object>> queue;

    public MediaOps(WhatsApi api, Map<String, Map<String, Object>> queue) {
        super(api);
        this.queue = queue;
    }

    /**
     * Send audio to the user/group.     *
     *
     * @return JSONObject json object with media information, or null if sending failed
     * @throws WhatsAppException
     */
    public void sendMessageAudio(String to, File filepath) throws WhatsAppException {
        sendMessageAudio(to, filepath, false);
    }

    /**
     * Send audio to the user/group.     *
     *
     * @return JSONObject json object with media information, or null if sending failed
     * @throws net.sumppen.whatsapi4j.WhatsAppException
     */
    public void sendMessageAudio(String to, File file, boolean storeURLmedia) throws WhatsAppException {
        MediaInfo info = new MediaInfo();
        info.setMediaFile(file);
        info.setCaption(null);
        try {
            sendCheckAndSendMedia(info, AUDIO_MAXSIZE, Lists.newArrayList(to), AUDIO_TYPE, AUDIO_EXTENSIONS);
        } catch (Exception e) {
            log.error("Exception sending audio", e);
            throw new WhatsAppException(e);
        }
    }

    /**
     * Send an image file to group/user
     *
     * @return JSONObject
     * @throws WhatsAppException
     */
    public void sendMessageImage(String to, File image, File preview) throws WhatsAppException {
        sendMessageImage(to, image, preview, null);
    }

    /**
     * Send an image file to group/user
     *
     * @return JSONObject
     * @throws WhatsAppException
     */
    public void sendMessageImage(String to, File image, File preview, String caption) throws WhatsAppException {
        MediaInfo info = new MediaInfo();
        info.setMediaFile(image);
        info.setPreviewFile(preview);
        info.setCaption(caption);
        try {
            sendCheckAndSendMedia(info, IMAGE_MAXSIZE, Lists.newArrayList(to), IMAGE_TYPE, IMAGE_EXTENSIONS);
        } catch (Exception e) {
            log.error("Exception sending image", e);
            throw new WhatsAppException(e);
        }
    }

    /**
     * Send a video to the user/group.
     *
     * @return boolean
     * @throws WhatsAppException
     */
    public void sendMessageVideo(String to, File media, File preview, String caption) throws WhatsAppException {
        MediaInfo info = new MediaInfo();
        info.setMediaFile(media);
        info.setPreviewFile(preview);
        info.setCaption(caption);
        try {
            sendCheckAndSendMedia(info, VIDEO_MAXSIZE, Lists.newArrayList(to), VIDEO_TYPE, VIDEO_EXTENSIONS);
        } catch (Exception e) {
            log.warn("Exception sending video", e);
            throw new WhatsAppException(e);
        }
    }

    public void sendBroadcastAudio(List<String> targets, String path) throws WhatsAppException {
        sendBroadcastAudio(targets, path, false);
    }

    /**
     * Send a Broadcast Message with audio.
     * <p>
     * The recipient MUST have your number (synced) and in their contact list
     * otherwise the message will not deliver to that person.
     * <p>
     * Approx 20 (unverified) is the maximum number of targets
     *
     * @throws WhatsAppException
     */
    public void sendBroadcastAudio(List<String> targets, String path, boolean storeURLmedia) throws WhatsAppException {
        //TODO implement this
        throw new WhatsAppException("Not yet implemented");
    }

    public void sendBroadcastImage(List<String> targets, String path) throws WhatsAppException {
        sendBroadcastImage(targets, path, false);
    }

    /**
     * Send a Broadcast Message with an image.
     * <p>
     * The recipient MUST have your number (synced) and in their contact list
     * otherwise the message will not deliver to that person.
     * <p>
     * Approx 20 (unverified) is the maximum number of targets
     *
     * @throws WhatsAppException
     */
    public void sendBroadcastImage(List<String> targets, String path, boolean storeURLmedia) throws WhatsAppException {
        //TODO implement this
        throw new WhatsAppException("Not yet implemented");
    }

    /**
     * Send a Broadcast Message with location data.
     * <p>
     * The recipient MUST have your number (synced) and in their contact list
     * otherwise the message will not deliver to that person.
     * <p>
     * If no name is supplied , receiver will see large sized google map
     * thumbnail of entered Lat/Long but NO name/url for location.
     * <p>
     * With name supplied, a combined map thumbnail/name box is displayed
     * <p>
     * Approx 20 (unverified) is the maximum number of targets
     *
     * @throws WhatsAppException
     */

    public void sendBroadcastLocation(List<String> targets, float lng, float lat, String name, String url) throws WhatsAppException {
        //TODO implement this
        throw new WhatsAppException("Not yet implemented");
    }

    /**
     * Send a Broadcast Message
     * <p>
     * The recipient MUST have your number (synced) and in their contact list
     * otherwise the message will not deliver to that person.
     * <p>
     * Approx 20 (unverified) is the maximum number of targets
     *
     * @throws WhatsAppException
     */
    public void sendBroadcastMessage(List<String> targets, String message) throws WhatsAppException {
        //TODO implement this
        throw new WhatsAppException("Not yet implemented");
    }

    public void sendBroadcastVideo(List<String> targets, String path) throws WhatsAppException {
        sendBroadcastVideo(targets, path, false);
    }

    /**
     * Send a location to the user/group.
     * <p>
     * If no name is supplied , receiver will see large sized google map
     * thumbnail of entered Lat/Long but NO name/url for location.
     * <p>
     * With name supplied, a combined map thumbnail/name box is displayed
     *
     * @throws WhatsAppException
     */
    public void sendMessageLocation(List<String> to, float lng, float lat, String name, String url) throws WhatsAppException {
        //TODO implement this
        throw new WhatsAppException("Not yet implemented");
    }


    /**
     * Send a Broadcast Message with a video.
     * <p>
     * The recipient MUST have your number (synced) and in their contact list
     * otherwise the message will not deliver to that person.
     * <p>
     * Approx 20 (unverified) is the maximum number of targets
     *
     * @throws WhatsAppException
     */
    public void sendBroadcastVideo(List<String> targets, String path, boolean storeURLmedia) throws WhatsAppException {
        //TODO implement this
        throw new WhatsAppException("Not yet implemented");
    }

    //todo check preview file.
    private void sendCheckAndSendMedia(MediaInfo info, int maxSize, List<String> tos, String type, String[] allowedExtensions) throws WhatsAppException, IncompleteMessageException, InvalidMessageException, InvalidTokenException, IOException, JSONException, NoSuchAlgorithmException, InvalidKeyException, DecodeException {
        File file = info.getMediaFile();

        Validate.isTrue(file.isFile());
        Validate.isTrue(file.canRead());
        Validate.isTrue(FilenameUtils.isExtension(file.getName(), allowedExtensions));
        Validate.exclusiveBetween(0, maxSize, file.length());

        sendRequestFileUpload(WhatsUtils.b64hash(file), type, info, tos);

    }

    private void sendRequestFileUpload(String b64hash, String type, MediaInfo mediaInfo, List<String> tos) throws WhatsAppException, IncompleteMessageException, InvalidMessageException, InvalidTokenException, IOException, JSONException, NoSuchAlgorithmException, InvalidKeyException, DecodeException {
        // mediaFile = file;
        final ProtocolNode mediaNode = new ProtocolNode("media");
        mediaNode.getAttributes().put("hash", b64hash);
        mediaNode.getAttributes().put("type", type);
        mediaNode.getAttributes().put("size", Long.toString(mediaInfo.getMediaFile().length()));

        final ProtocolNode node = new ProtocolNode("iq");
        final String uploadId = createMsgId("upload");
        node.getAttributes().put("id", uploadId);
        node.getAttributes().put("to", WhatsApi.WHATSAPP_SERVER);
        node.getAttributes().put("type", "set");
        node.getAttributes().put("xmlns", "w:m");
        node.getChildren().add(mediaNode);

        final String messageId = createMsgId("message");
        final Map<String, Object> map = Maps.newHashMap();
        //este me parece que no es necesario.
        map.put("messageNode", node);
        map.put("mediaInfo", mediaInfo);
        map.put("to", tos);
        map.put("message_id", messageId);
        queue.put(uploadId, map);
        sendNode(node);
    }

    /**
     * Send a vCard to the user/group.
     *
     * @throws WhatsAppException
     */
    public void sendVcard(String to, String name, Object vCard) throws WhatsAppException {
        //TODO implement this
        throw new WhatsAppException("Not yet implemented");
    }
}
