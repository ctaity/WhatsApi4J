package net.sumppen.whatsapi4j.async;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToByteEncoder;
import net.sumppen.whatsapi4j.BinTreeNodeWriter;
import net.sumppen.whatsapi4j.ProtocolNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by taity on 6/19/15.
 */
public class WhatsAppEncoder extends MessageToByteEncoder<ProtocolNode> {

    private final static Logger log = LoggerFactory.getLogger(WhatsAppEncoder.class);
    private final BinTreeNodeWriter writer = new BinTreeNodeWriter();


    public BinTreeNodeWriter getWriter() {
        return writer;
    }

    @Override
    protected void encode(ChannelHandlerContext ctx, ProtocolNode msg, ByteBuf out) throws Exception {
        log.debug("-->>> {}", msg.toString());
        out.writeBytes(writer.write(msg, true));
    }
}