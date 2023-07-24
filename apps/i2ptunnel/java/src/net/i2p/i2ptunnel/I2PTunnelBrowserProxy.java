package net.i2p.i2ptunnel;

import java.net.Socket;
import java.util.StringTokenizer;

import net.i2p.client.streaming.I2PSocketManager;
import net.i2p.util.EventDispatcher;

public class I2PTunnelBrowserProxy extends I2PTunnelHTTPClientBase implements Runnable {
    private final String _proxyNonce;

    /**
     * This constructor always starts the tunnel (ignoring the i2cp.delayOpen
     * option).
     * It is used to add a client to an existing socket manager.
     *
     * As of 0.9.20 this is fast, and does NOT connect the manager to the router,
     * or open the local socket. You MUST call startRunning() for that.
     *
     * @param sockMgr the existing socket manager
     */
    public I2PTunnelBrowserProxy(int localPort, Logging l, I2PSocketManager sockMgr, I2PTunnel tunnel,
            EventDispatcher notifyThis, long clientId) {
        super(localPort, l, sockMgr, tunnel, notifyThis, clientId);
        _proxyNonce = Long.toString(_context.random().nextLong());
        // proxyList = new ArrayList();

        setName("HTTP Proxy on " + getTunnel().listenHost + ':' + localPort);
        notifyEvent("openHTTPClientResult", "ok");
    }

    /**
     * As of 0.9.20 this is fast, and does NOT connect the manager to the router,
     * or open the local socket. You MUST call startRunning() for that.
     *
     * @throws IllegalArgumentException if the I2PTunnel does not contain
     *                                  valid config to contact the router
     */
    public I2PTunnelBrowserProxy(int localPort, Logging l, boolean ownDest,
            String wwwProxy, EventDispatcher notifyThis,
            I2PTunnel tunnel) throws IllegalArgumentException {
        super(localPort, ownDest, l, notifyThis, "HTTP Proxy on " + tunnel.listenHost + ':' + localPort, tunnel);
        _proxyNonce = Long.toString(_context.random().nextLong());

        // proxyList = new ArrayList(); // We won't use outside of i2p

        if (wwwProxy != null) {
            StringTokenizer tok = new StringTokenizer(wwwProxy, ", ");
            while (tok.hasMoreTokens()) {
                _proxyList.add(tok.nextToken().trim());
            }
        }

        setName("HTTP Proxy on " + tunnel.listenHost + ':' + localPort);
        notifyEvent("openHTTPClientResult", "ok");
    }

    @Override
    protected void clientConnectionRun(Socket s) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'clientConnectionRun'");
    }

    @Override
    protected String getRealm() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getRealm'");
    }

}
