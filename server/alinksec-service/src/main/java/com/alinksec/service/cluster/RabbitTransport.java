package com.alinksec.service.cluster;

import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import jakarta.annotation.PreDestroy;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/** Broker messages are bounded SQL row identifiers; report bytes stay in the authenticated inbox. */
@Component
public class RabbitTransport {
    private final ClusterProperties properties;
    private final Object producerLock=new Object();
    private final Object[] consumerLocks={new Object(),new Object()};
    private final Channel[] consumers=new Channel[2];
    private final AtomicBoolean returned=new AtomicBoolean();
    private final AtomicLong malformed=new AtomicLong();
    private Connection connection;
    private Channel producer;

    public RabbitTransport(ClusterProperties properties) { this.properties=properties; }

    public String queueName() { return "alinksec."+properties.getDeploymentId()+".reports"; }

    private synchronized Connection connection() {
        if(!properties.isEnabled()) throw new IllegalStateException("cluster_disabled");
        if(connection!=null && connection.isOpen()) return connection;
        try {
            var factory=new ConnectionFactory();
            factory.setUri(properties.getRabbitUri());
            if(factory.isSSL()) {
                factory.useSslProtocol(javax.net.ssl.SSLContext.getDefault());
                factory.enableHostnameVerification();
            }
            factory.setConnectionTimeout(2000);factory.setHandshakeTimeout(3000);
            factory.setRequestedHeartbeat(10);factory.setAutomaticRecoveryEnabled(false);
            factory.setShutdownTimeout(2000);
            connection=factory.newConnection("alinksec-"+properties.getDeploymentId()+"-"+properties.getNodeId());
            producer=null;consumers[0]=null;consumers[1]=null;
            return connection;
        } catch(Exception failure) { throw new ClusterUnavailable("rabbit_unavailable"); }
    }

    private Channel channel(boolean publishing) throws java.io.IOException {
        Channel channel=connection().createChannel();
        if(channel==null) throw new ClusterUnavailable("rabbit_channel_capacity");
        try {
            channel.queueDeclare(queueName(),true,false,false,Map.of(
                    "x-queue-type","quorum","x-max-length",properties.getMaxPendingReports(),
                    "x-max-length-bytes",4<<20,"x-overflow","reject-publish"));
            if(publishing) {
                channel.confirmSelect();
                channel.addReturnListener(message->returned.set(true));
            } else channel.basicQos(1);
            return channel;
        } catch(RuntimeException | java.io.IOException failure) {
            channel.abort();throw failure;
        }
    }

    public void publish(String id) {
        if(!id.matches("[a-f0-9-]{36}")) throw new IllegalArgumentException("invalid_queue_hint");
        synchronized(producerLock) {
            try {
                connection();
                if(producer==null || !producer.isOpen()) producer=channel(true);
                returned.set(false);
                producer.basicPublish("",queueName(),true,new AMQP.BasicProperties.Builder()
                        .deliveryMode(2).contentType("text/plain").messageId(id).build(),id.getBytes(StandardCharsets.US_ASCII));
                producer.waitForConfirmsOrDie(2000);
                if(returned.get()) throw new ClusterUnavailable("rabbit_hint_unroutable");
            } catch(Exception failure) {
                if(failure instanceof InterruptedException) Thread.currentThread().interrupt();
                if(producer!=null) try { producer.abort(); } catch(Exception ignored) { }
                producer=null;
                throw new ClusterUnavailable("rabbit_publish_unconfirmed");
            }
        }
    }

    /** Handler must return after its SQL transaction commits; only then is the exact channel ACK sent. */
    public boolean receive(int lane,Consumer<String> handler) {
        if(lane<0 || lane>=consumers.length) throw new IllegalArgumentException("invalid_consumer_lane");
        synchronized(consumerLocks[lane]) {
            Channel channel=null;long tag=0;
            try {
                connection();
                if(consumers[lane]==null || !consumers[lane].isOpen()) consumers[lane]=channel(false);
                channel=consumers[lane];
                var message=channel.basicGet(queueName(),false);
                if(message==null) return false;
                tag=message.getEnvelope().getDeliveryTag();
                byte[] body=message.getBody();
                String id=body.length==36 ? new String(body,StandardCharsets.US_ASCII) : "";
                if(!id.matches("[a-f0-9-]{36}")) {
                    malformed.incrementAndGet();channel.basicReject(tag,false);return true;
                }
                handler.accept(id);
                channel.basicAck(tag,false);
                return true;
            } catch(Exception failure) {
                if(channel!=null && channel.isOpen() && tag!=0) {
                    try { channel.basicNack(tag,false,true); }
                    catch(Exception ignored) { /* Broker redelivers unacknowledged hints after connection loss. */ }
                }
                throw new ClusterUnavailable("rabbit_consumer_unavailable");
            }
        }
    }

    public boolean healthy() {
        synchronized(producerLock) {
            try {
                connection();
                if(producer==null || !producer.isOpen()) producer=channel(true);
                producer.queueDeclarePassive(queueName());
                return true;
            } catch(Exception failure) { return false; }
        }
    }
    public long malformedHints() { return malformed.get(); }

    @PreDestroy
    public synchronized void close() {
        if(connection!=null) { try { connection.abort(2000); } catch(Exception ignored) { } }
        connection=null;producer=null;consumers[0]=null;consumers[1]=null;
    }
}
