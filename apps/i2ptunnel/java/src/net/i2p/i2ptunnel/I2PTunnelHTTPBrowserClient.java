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
import net.i2p.util.ConvertToHash;
import net.i2p.util.DNSOverHTTPS;
import net.i2p.util.EventDispatcher;
import net.i2p.util.InternalSocket;
import net.i2p.util.Log;
import net.i2p.util.PortMapper;

/**
 * Act as a multiplexer of I2PTunnelHTTPClients with different ports on a single
 * port.
 * Dynamically creates a new I2PTunnelHTTPClient on a per-host basis.
 * For each new host, it creates a new I2PTunnelHTTPClient.
 * Each I2PTunnelHTTPClient is used for requests from a single specific origin.
 *
 */
public class I2PTunnelHTTPBrowserClient extends I2PTunnelHTTPClient {
    HashMap<String, I2PTunnelHTTPClient> clients = new HashMap<String, I2PTunnelHTTPClient>();
    private InternalSocketRunner isr;
    private static final boolean DEFAULT_KEEPALIVE_BROWSER = true;

    /**
     *
     */
    public I2PTunnelHTTPBrowserClient(int localPort, Logging l, I2PSocketManager sockMgr, I2PTunnel tunnel,
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
            I2PTunnel tunnel) throws IllegalArgumentException {
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
            defaultOpts.setProperty(I2PSocketOptions.PROP_READ_TIMEOUT, "" + I2PTunnelHTTPClient.DEFAULT_READ_TIMEOUT);
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
            defaultOpts.setProperty(I2PSocketOptions.PROP_READ_TIMEOUT, "" + I2PTunnelHTTPClient.DEFAULT_READ_TIMEOUT);
        }
        if (!defaultOpts.contains("i2p.streaming.inactivityTimeout")) {
            defaultOpts.setProperty("i2p.streaming.inactivityTimeout", "" + I2PTunnelHTTPClient.DEFAULT_READ_TIMEOUT);
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
            _context.portMapper().register(PortMapper.SVC_HTTP_PROXY_TABBED, getTunnel().listenHost, port);
            _context.portMapper().register(PortMapper.SVC_HTTPS_PROXY_TABBED, getTunnel().listenHost, port);
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
        _context.portMapper().register(PortMapper.SVC_HTTP_PROXY_TABBED + "@" + hostname, getTunnel().listenHost, port);
        _context.portMapper().register(PortMapper.SVC_HTTPS_PROXY_TABBED + "@" + hostname, getTunnel().listenHost,
                port);
    }

    private void unmapPort(String hostname) {
        _context.portMapper().unregister(PortMapper.SVC_HTTP_PROXY_TABBED + "@" + hostname);
        _context.portMapper().unregister(PortMapper.SVC_HTTPS_PROXY_TABBED + "@" + hostname);
    }

    private int findRandomOpenPort() throws IOException {
        try (
                ServerSocket socket = new ServerSocket(0);) {
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
        try {
            int port = findRandomOpenPort();
            I2PTunnelHTTPClient client = new I2PTunnelHTTPClient(port, l, _ownDest, hostname, getEventDispatcher(),
                    getTunnel());
            clients.put(hostname, client);
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

        /**
         * The URL after fixup, always starting with http:// or https://
         */
        String targetRequest = null;

        // in-net outproxy
        boolean usingWWWProxy = false;
        // local outproxy plugin
        boolean usingInternalOutproxy = false;
        Outproxy outproxy = null;
        boolean usingInternalServer = false;
        String internalPath = null;
        String internalRawQuery = null;
        String currentProxy = null;
        long requestId = __requestId.incrementAndGet();
        boolean shout = false;
        boolean isConnect = false;
        boolean isHead = false;
        I2PSocket i2ps = null;
        try {
            s.setSoTimeout(INITIAL_SO_TIMEOUT);
            out = s.getOutputStream();
            InputReader reader = new InputReader(s.getInputStream());
            int requestCount = 0;
            // HTTP Persistent Connections (RFC 2616)
            // for the local browser-to-client-proxy socket.
            // Keep it very simple.
            // Will be set to false for non-GET/HEAD, non-HTTP/1.1,
            // Connection: close, InternalSocket,
            // or after analysis of the response headers in HTTPResponseOutputStream,
            // or on errors in I2PTunnelRunner.
            boolean keepalive = getBooleanOption(OPT_KEEPALIVE_BROWSER, DEFAULT_KEEPALIVE_BROWSER) &&
                                !(s instanceof InternalSocket);

          // indent
          do {   // while (keepalive)
          // indent

            if (requestCount > 0) {
                try {
                    s.setSoTimeout(BROWSER_KEEPALIVE_TIMEOUT);
                } catch (IOException ioe) {
                    if (_log.shouldInfo())
                        _log.info("Socket closed before request #" + requestCount);
                    return;
                }
                if (_log.shouldInfo())
                    _log.info("Keepalive, awaiting request #" + requestCount);
            }
            String line, method = null, protocol = null, host = null, destination = null;
            String hostLowerCase = null;
            StringBuilder newRequest = new StringBuilder();
            boolean ahelperPresent = false;
            boolean ahelperNew = false;
            String ahelperKey = null;
            String userAgent = null;
            String authorization = null;
            int remotePort = 0;
            String referer = null;
            URI origRequestURI = null;
            boolean preserveConnectionHeader = false;
            boolean allowGzip = false;
            while((line = reader.readLine(method)) != null) {
                line = line.trim();
                if(_log.shouldLog(Log.DEBUG)) {
                    _log.debug(getPrefix(requestId) + "Line=[" + line + "]");
                }

                String lowercaseLine = line.toLowerCase(Locale.US);

                if(method == null) {
                    // first line GET/POST/etc.
                    if (_log.shouldInfo())
                        _log.info(getPrefix(requestId) + "req #" + requestCount + " first line [" + line + "]");

                    String[] params = DataHelper.split(line, " ", 3);
                    if(params.length != 3) {
                        break;
                    }
                    String request = fixupRequest(params[0], params[1]);

                    method = params[0].toUpperCase(Locale.US);
                    if (method.equals("HEAD")) {
                        isHead = true;
                    } else if (method.equals("CONNECT")) {
                        // this makes things easier later, by spoofing a
                        // protocol so the URI parser find the host and port
                        // For in-net outproxy, will be fixed up below
                        isConnect = true;
                        keepalive = false;
                    } else if (!method.equals("GET")) {
                        // POST, PUT, ...
                        keepalive = false;
                    }

                    // Now use the Java URI parser
                    // This will be the incoming URI but will then get modified
                    // to be the outgoing URI (with http:// if going to outproxy, otherwise without)
                    URI requestURI = null;
                    try {
                        try {
                            requestURI = new URI(request);
                        } catch(URISyntaxException use) {
                            // fixup []| in path/query not escaped by browsers, see ticket #2130
                            boolean error = true;
                            // find 3rd /
                            int idx = 0;
                            for (int i = 0; i < 2; i++) {
                                idx = request.indexOf('/', idx);
                                if (idx < 0)
                                    break;
                                idx++;
                            }
                            if (idx > 0) {
                                String schemeHostPort = request.substring(0, idx);
                                String rest = request.substring(idx);
                                // not escaped by all browsers, may be specific to query, see ticket #2130
                                rest = rest.replace("[", "%5B");
                                rest = rest.replace("]", "%5D");
                                rest = rest.replace("|", "%7C");
                                rest = rest.replace("{", "%7B");
                                rest = rest.replace("}", "%7D");
                                String testRequest = schemeHostPort + rest;
                                if (!testRequest.equals(request)) {
                                    try {
                                        requestURI = new URI(testRequest);
                                        request = testRequest;
                                        error = false;
                                    } catch(URISyntaxException use2) {
                                        // didn't work, give up
                                    }
                                }
                            }
                            // guess it wasn't []|
                            if (error)
                                throw use;
                        }
                        origRequestURI = requestURI;
                        String hostName = requestURI.getHost();
                        if(hostName != null) {
                            host = hostName;
                            hostLowerCase = host.toLowerCase(Locale.US);
                        }
                        /**
                         * This is where the host-specific logic happens
                         */
                    } catch(URISyntaxException use) {
                        if(_log.shouldLog(Log.WARN)) {
                            _log.warn(getPrefix(requestId) + "Bad request [" + request + "]", use);
                        }
                        try {
                            out.write(getErrorPage("baduri", ERR_BAD_URI).getBytes("UTF-8"));
                            String msg = use.getLocalizedMessage();
                            if (msg != null) {
                                out.write(DataHelper.getASCII("<p>\n"));
                                out.write(DataHelper.getUTF8(DataHelper.escapeHTML(msg)));
                                out.write(DataHelper.getASCII("</p>\n"));
                            }
                            out.write(DataHelper.getASCII("</div>\n"));
                            writeFooter(out);
                            reader.drain();
                        } catch (IOException ioe) {
                            // ignore
                        }
                        return;
                    }
                }
            }
        } while (keepalive);
    }  catch(IOException ex) {
        // This is normal for keepalive when the browser closed the socket,
        // or a SocketTimeoutException if we gave up first
        if(_log.shouldLog(Log.INFO)) {
            _log.info(getPrefix(requestId) + "Error trying to connect", ex);
        }
        handleClientException(ex, out, targetRequest, usingWWWProxy, currentProxy, requestId);
    /*} catch(I2PException ex) {
        if(_log.shouldLog(Log.INFO)) {
            _log.info(getPrefix(requestId) + "Error trying to connect", ex);
        }
        handleClientException(ex, out, targetRequest, usingWWWProxy, currentProxy, requestId);*/
    /*} catch(OutOfMemoryError oom) {
        IOException ex = new IOException("OOM");
        _log.error(getPrefix(requestId) + "Error trying to connect", oom);
        handleClientException(ex, out, targetRequest, usingWWWProxy, currentProxy, requestId);*/
    } finally {
        // only because we are running it inline
        closeSocket(s);
        if (i2ps != null) try { i2ps.close(); } catch (IOException ioe) {}
    }
}
}
