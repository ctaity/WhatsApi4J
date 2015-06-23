package net.sumppen.whatsapi4j.async;

import com.sun.tools.javac.util.Assert;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ReplayingDecoder;
import net.sumppen.whatsapi4j.BinTreeNodeReader;
import net.sumppen.whatsapi4j.ProtocolNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Created by taity on 6/19/15.
 */
//prodia agregar states;
public class WhatsAppDecoder extends ReplayingDecoder {

    private final static Logger log = LoggerFactory.getLogger(WhatsAppDecoder.class);
    private final BinTreeNodeReader reader = new BinTreeNodeReader();

    public BinTreeNodeReader getReader() {
        return reader;
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf msg, List<Object> out) throws Exception {
        msg.markReaderIndex();
        final byte[] buf = new byte[3];
        msg.readBytes(buf);
        int treeLength = ((buf[0] & 0x0f) & 0xFF) << 16;
        treeLength += (buf[1] & 0xFF) << 8;
        treeLength += (buf[2] & 0xFF) << 0;

        log.trace("Packet arrive length:{}", treeLength);
        final byte[] msgdata = new byte[treeLength + 3];
        msg.resetReaderIndex();
        msg.readBytes(msgdata);
        ProtocolNode node = reader.nextTree(msgdata);
        log.debug("<<<--- {} ", node.toString());
        out.add(node);
    }
}
