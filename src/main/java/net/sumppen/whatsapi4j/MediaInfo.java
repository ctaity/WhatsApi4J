package net.sumppen.whatsapi4j;

import java.io.File;

public class MediaInfo {
    private File mediaFile;
    private File previewFile;
    private String caption;

    public File getMediaFile() {
        return mediaFile;
    }

    public void setMediaFile(File mediaFile) {
        this.mediaFile = mediaFile;
    }

    public File getPreviewFile() {
        return previewFile;
    }

    public void setPreviewFile(File previewFile) {
        this.previewFile = previewFile;
    }

    public String getCaption() {
        return caption;
    }

    public void setCaption(String caption) {
        this.caption = caption;
    }
}
