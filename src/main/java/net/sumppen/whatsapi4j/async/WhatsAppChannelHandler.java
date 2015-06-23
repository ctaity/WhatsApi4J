package net.sumppen.whatsapi4j.async;

import com.sun.tools.javac.util.Assert;
import io.netty.channel.ChannelHandlerAdapter;
import io.netty.channel.ChannelHandlerContext;
import net.sumppen.whatsapi4j.*;
import org.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by taity on 6/19/15.
 */
public class WhatsAppChannelHandler extends ChannelHandlerAdapter {
    private final static Logger log = LoggerFactory.getLogger(WhatsAppChannelHandler.class);
    private WhatsApi api;


    public WhatsAppChannelHandler(WhatsApi api) {
        Assert.checkNonNull(api);
        this.api = api;
    }



    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (!(msg instanceof ProtocolNode)) {
            log.error("Warning msg is not for me");
            return;
        }

        ProtocolNode node = (ProtocolNode) msg;
        log.debug("Proccesing protocol node:{}", node.getTag());
        try {
            api.processInboundDataNode(node);
        } catch (IncompleteMessageException e) {
            e.printStackTrace();
        } catch (InvalidMessageException e) {
            e.printStackTrace();
        } catch (InvalidTokenException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (WhatsAppException e) {
            e.printStackTrace();
        } catch (JSONException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (DecodeException e) {
            e.printStackTrace();
        } catch (EncodeException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        System.out.println("Chau mundo ......");
        cause.printStackTrace();
        ctx.close();
    }
}
