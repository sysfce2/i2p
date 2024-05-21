/* I2PTunnel is GPL'ed (with the exception mentioned in I2PTunnel.java)
 * (c) 2003 - 2004 mihi
 */
package net.i2p.i2ptunnel;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.concurrent.ConcurrentHashMap;
import net.i2p.I2PAppContext;
import net.i2p.I2PException;
import net.i2p.app.ClientApp;
import net.i2p.app.ClientAppManager;
import net.i2p.app.Outproxy;
import net.i2p.client.I2PSession;
import net.i2p.client.LookupResult;
import net.i2p.client.streaming.I2PSocket;
import net.i2p.client.streaming.I2PSocketManager;
import net.i2p.client.streaming.I2PSocketOptions;
import net.i2p.crypto.Blinding;
import net.i2p.crypto.SHA256Generator;
import net.i2p.data.Base32;
import net.i2p.data.Base64;
import net.i2p.data.BlindData;
import net.i2p.data.DataHelper;
import net.i2p.data.Destination;
import net.i2p.data.Hash;
import net.i2p.i2ptunnel.localServer.LocalHTTPServer;
import net.i2p.i2ptunnel.util.HTTPRequestReader;
import net.i2p.i2ptunnel.util.InputReader;
import net.i2p.util.ConvertToHash;
import net.i2p.util.DNSOverHTTPS;
import net.i2p.util.EventDispatcher;
import net.i2p.util.InternalSocket;
import net.i2p.util.Log;
import net.i2p.util.PortMapper;

/**
 * Act as a multiplexer of I2PTunnelHTTPClients with different ports on a
 * single port. Dynamically creates a new I2PTunnelHTTPClient on a per-host
 * basis. For each new host, it creates a new I2PTunnelHTTPClient. Each
 * I2PTunnelHTTPClient is used for requests from a single specific origin.
 *
 */
public class I2PTunnelHTTPBrowserClient extends I2PTunnelHTTPClient {
    HashMap<Destination, I2PTunnelHTTPClient> clients = new HashMap<Destination, I2PTunnelHTTPClient>();
    private InternalSocketRunner isr;
    private static final boolean DEFAULT_KEEPALIVE_BROWSER = true;

    /**
     *
     */
    public I2PTunnelHTTPBrowserClient(int localPort, Logging l,
            I2PSocketManager sockMgr, I2PTunnel tunnel,
            EventDispatcher notifyThis, long clientId) {
        super(localPort, l, sockMgr, tunnel, notifyThis, clientId);
        setName("HTTP Proxy on " + tunnel.listenHost + ':' + localPort);
        notifyEvent("openHTTPClientResult", "ok");
    }

    /**
     *
     */
    public I2PTunnelHTTPBrowserClient(int localPort, Logging l, boolean ownDest,
            String wwwProxy, EventDispatcher notifyThis,
            I2PTunnel tunnel)
            throws IllegalArgumentException {
        super(localPort, l, ownDest, wwwProxy, notifyThis, tunnel);
        setName("HTTP Proxy on " + tunnel.listenHost + ':' + localPort);
        notifyEvent("openHTTPClientResult", "ok");
    }

    /**
     * Create the default options (using the default timeout, etc).
     * Warning, this does not make a copy of I2PTunnel's client options,
     * it modifies them directly.
     * unused?
     *
     * This will throw IAE on tunnel build failure
     */
    @Override
    protected I2PSocketOptions getDefaultOptions() {
        Properties defaultOpts = getTunnel().getClientOptions();
        if (!defaultOpts.contains(I2PSocketOptions.PROP_READ_TIMEOUT)) {
            defaultOpts.setProperty(I2PSocketOptions.PROP_READ_TIMEOUT,
                    "" + I2PTunnelHTTPClient.DEFAULT_READ_TIMEOUT);
        }
        // if (!defaultOpts.contains("i2p.streaming.inactivityTimeout"))
        // defaultOpts.setProperty("i2p.streaming.inactivityTimeout",
        // ""+DEFAULT_READ_TIMEOUT);
        // delayed start
        verifySocketManager();
        I2PSocketOptions opts = sockMgr.buildOptions(defaultOpts);
        if (!defaultOpts.containsKey(I2PSocketOptions.PROP_CONNECT_TIMEOUT)) {
            opts.setConnectTimeout(DEFAULT_CONNECT_TIMEOUT);
        }
        return opts;
    }

    /**
     * Create the default options (using the default timeout, etc).
     * Warning, this does not make a copy of I2PTunnel's client options,
     * it modifies them directly.
     * Do not use overrides for per-socket options.
     *
     * This will throw IAE on tunnel build failure
     */
    @Override
    protected I2PSocketOptions getDefaultOptions(Properties overrides) {
        Properties defaultOpts = getTunnel().getClientOptions();
        defaultOpts.putAll(overrides);
        if (!defaultOpts.contains(I2PSocketOptions.PROP_READ_TIMEOUT)) {
            defaultOpts.setProperty(I2PSocketOptions.PROP_READ_TIMEOUT,
                    "" + I2PTunnelHTTPClient.DEFAULT_READ_TIMEOUT);
        }
        if (!defaultOpts.contains("i2p.streaming.inactivityTimeout")) {
            defaultOpts.setProperty("i2p.streaming.inactivityTimeout",
                    "" + I2PTunnelHTTPClient.DEFAULT_READ_TIMEOUT);
        }
        // delayed start
        verifySocketManager();
        I2PSocketOptions opts = sockMgr.buildOptions(defaultOpts);
        if (!defaultOpts.containsKey(I2PSocketOptions.PROP_CONNECT_TIMEOUT)) {
            opts.setConnectTimeout(DEFAULT_CONNECT_TIMEOUT);
        }
        return opts;
    }

    /**
     * Actually start working on incoming connections.
     * Overridden to start an internal socket too.
     *
     */
    @Override
    public void startRunning() {
        super.startRunning();
        if (open) {
            this.isr = new InternalSocketRunner(this);
            this.isr.start();
            int port = getLocalPort();
            _context.portMapper().register(PortMapper.SVC_HTTP_PROXY_TABBED,
                    getTunnel().listenHost, port);
            _context.portMapper().register(PortMapper.SVC_HTTPS_PROXY_TABBED,
                    getTunnel().listenHost, port);
        }
    }

    /**
     * Overridden to close internal socket too.
     */
    @Override
    public boolean close(boolean forced) {
        int port = getLocalPort();
        int reg = _context.portMapper().getPort(PortMapper.SVC_HTTP_PROXY_TABBED);
        if (reg == port) {
            _context.portMapper().unregister(PortMapper.SVC_HTTP_PROXY_TABBED);
        }
        reg = _context.portMapper().getPort(PortMapper.SVC_HTTPS_PROXY_TABBED);
        if (reg == port) {
            _context.portMapper().unregister(PortMapper.SVC_HTTPS_PROXY_TABBED);
        }
        boolean rv = super.close(forced);
        if (this.isr != null) {
            this.isr.stopRunning();
        }
        return rv;
    }

    private void mapPort(String hostname, int port) {
        _context.portMapper().register(PortMapper.SVC_HTTP_PROXY_TABBED + "@" +
                hostname,
                getTunnel().listenHost, port);
        _context.portMapper().register(PortMapper.SVC_HTTPS_PROXY_TABBED + "@" +
                hostname,
                getTunnel().listenHost, port);
    }

    private void unmapPort(String hostname) {
        _context.portMapper().unregister(PortMapper.SVC_HTTP_PROXY_TABBED + "@" +
                hostname);
        _context.portMapper().unregister(PortMapper.SVC_HTTPS_PROXY_TABBED + "@" +
                hostname);
    }

    private int findRandomOpenPort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0);) {
            return socket.getLocalPort();
        }
    }

    public I2PTunnelHTTPClient getI2PTunnelHTTPClient(URI uri) {
        String hostname = uri.getHost();
        return getI2PTunnelHTTPClient(hostname);
    }

    public I2PTunnelHTTPClient getI2PTunnelHTTPClient(String hostname) {
        if (hostname == null)
            return null;
        return clients.get(hostname);
    }

    protected boolean mapNewClient(URI uri) {
        String hostname = uri.getHost();
        if (hostname == null)
            return false;
        Destination destination = _context.namingService().lookup(hostname);
        if (destination == null)
            return false;
        try {
            int port = findRandomOpenPort();
            I2PTunnelHTTPClient client = new I2PTunnelHTTPClient(
                    port, l, _ownDest, hostname, getEventDispatcher(), getTunnel());
            clients.put(destination, client);
            getI2PTunnelHTTPClient(hostname).startRunning();
            mapPort(hostname, port);
        } catch (IOException e) {
            throw new RuntimeException("Failed to find a random open port", e);
        }
        return true;
    }

    protected boolean unmapClient(URI uri) {
        String hostname = uri.getHost();
        if (hostname == null)
            return false;
        getI2PTunnelHTTPClient(hostname).close(true);
        unmapPort(hostname);
        return true;
    }

    @Override
    protected void clientConnectionRun(Socket s) {
        OutputStream out = null;

        // in-net outproxy
        boolean usingWWWProxy = false;

        long requestId = __requestId.incrementAndGet();
        I2PSocket i2ps = null;
        try {
            s.setSoTimeout(INITIAL_SO_TIMEOUT);
            out = s.getOutputStream();
            InputReader reader = new InputReader(s.getInputStream());
            HTTPRequestReader hrr = new HTTPRequestReader(s, _context, reader, usingWWWProxy, __requestId, BROWSER_READ_TIMEOUT, getTunnel(), null);
            _log.debug(hrr.toString());
            // HTTP Persistent Connections (RFC 2616)
            // for the local browser-to-client-proxy socket.
            // Keep it very simple.
            // Will be set to false for non-GET/HEAD, non-HTTP/1.1,
            // Connection: close, InternalSocket,
            // or after analysis of the response headers in
            // HTTPResponseOutputStream, or on errors in I2PTunnelRunner.
            boolean keepalive = getBooleanOption(OPT_KEEPALIVE_BROWSER, DEFAULT_KEEPALIVE_BROWSER) &&
                    !(s instanceof InternalSocket);

            // indent
            do {

            } while (keepalive);
        } catch (IOException ex) {
            // This is normal for keepalive when the browser closed the socket,
            // or a SocketTimeoutException if we gave up first
            if (_log.shouldLog(Log.INFO)) {
                _log.info(getPrefix(requestId) + "Error trying to connect", ex);
            }
            /*handleClientException(ex, out, targetRequest, usingWWWProxy, currentProxy,
                    requestId);*/
            /*
             * } catch(I2PException ex) {
             * if(_log.shouldLog(Log.INFO)) {
             * _log.info(getPrefix(requestId) + "Error trying to connect",
             * ex);
             * }
             * handleClientException(ex, out, targetRequest, usingWWWProxy,
             * currentProxy, requestId);
             */
            /*
             * } catch(OutOfMemoryError oom) {
             * IOException ex = new IOException("OOM");
             * _log.error(getPrefix(requestId) + "Error trying to connect", oom);
             * handleClientException(ex, out, targetRequest, usingWWWProxy,
             * currentProxy, requestId);
             */
        } finally {
            // only because we are running it inline
            closeSocket(s);
            if (i2ps != null)
                try {
                    i2ps.close();
                } catch (IOException ioe) {
                }
        }
    }
}
