package net.i2p.i2ptunnel;

import net.i2p.client.streaming.I2PSocketManager;
import net.i2p.util.EventDispatcher;

public class I2PTunnelHTTPBrowserClient extends I2PTunnelHTTPClient {

    public I2PTunnelHTTPBrowserClient(int localPort, Logging l, boolean ownDest, String wwwProxy,
            EventDispatcher notifyThis, I2PTunnel tunnel) throws IllegalArgumentException {
        super(localPort, l, ownDest, wwwProxy, notifyThis, tunnel);
        // TODO Auto-generated constructor stub
    }

    public I2PTunnelHTTPBrowserClient(int localPort, Logging l, I2PSocketManager sockMgr, I2PTunnel tunnel,
            EventDispatcher notifyThis, long clientId) {
        super(localPort, l, sockMgr, tunnel, notifyThis, clientId);
        // TODO Auto-generated constructor stub
    }

}
