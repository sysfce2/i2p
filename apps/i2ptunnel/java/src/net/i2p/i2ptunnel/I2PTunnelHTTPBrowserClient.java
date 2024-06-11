/* I2PTunnel is GPL'ed (with the exception mentioned in I2PTunnel.java)
 * (c) 2003 - 2004 mihi
 */
package net.i2p.i2ptunnel;

import java.io.IOException;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Locale;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicLong;

import net.i2p.I2PException;
import net.i2p.client.I2PSession;
import net.i2p.client.LookupResult;
import net.i2p.client.streaming.I2PSocket;
import net.i2p.client.streaming.I2PSocketOptions;
import net.i2p.crypto.Blinding;
import net.i2p.data.Base32;
import net.i2p.data.BlindData;
import net.i2p.data.Destination;
import net.i2p.data.Hash;
import net.i2p.i2ptunnel.localServer.LocalHTTPServer;
import net.i2p.i2ptunnel.util.HTTPRequestReader;
import net.i2p.i2ptunnel.util.InputReader;
import net.i2p.util.Log;
import net.i2p.util.PortMapper;
import net.i2p.util.SimpleTimer;
import net.i2p.util.SimpleTimer2;

/**
 * Act as a multiplexer of I2PTunnelHTTPClients with different ports on a single
 * port.
 * Dynamically creates a new I2PTunnelHTTPClient on a per-host basis.
 * For each new host with an in-I2P Destination, it creates a new
 * I2PTunnelHTTPClient.
 * Each I2PTunnelHTTPClient is used for talking to a specific destination, and
 * has it's own specific destination.
 * There is a 1/1 relationship between HTTP Client destinations and HTTP Server
 * destinations in I2P with this proxy.
 * An additional I2PTunnelHTTPClient is created upon startup, which is used for
 * all OutProxy traffic(which does not have an in-I2P Destination).
 *
 * It implements I2P Proposal #166: Identity-Aware HTTP Proxy, per the design as
 * of 05/29/2024
 *
 * @author idk
 * @since 0.9.62
 */
public class I2PTunnelHTTPBrowserClient extends I2PTunnelHTTPClientBase {
    public static final boolean DEFAULT_KEEPALIVE_BROWSER = true;
    public static final String AUTH_REALM = "I2P Browser Proxy";
    public static final int INBOUND_DEFAULT_LENGTH = 1;
    public static final int OUTBOUND_DEFAULT_LENGTH = 1;
    protected static final AtomicLong __requestId = new AtomicLong();
    HashMap<Hash, I2PTunnelHTTPClient> clients = new HashMap<Hash, I2PTunnelHTTPClient>();
    private InternalSocketRunner isr;
    private I2PTunnelFIFOQueue ffq = new I2PTunnelFIFOQueue();

    public I2PTunnelHTTPBrowserClient(final int clientPort, final Logging l, final boolean ownDest, final String proxy,
            final I2PTunnel i2pTunnel,
            final I2PTunnel tunnel) {
        super(clientPort, ownDest, l, i2pTunnel, proxy, tunnel);
        ffq.schedule(5 * 60 * 1000L);
        // setName(AUTH_REALM + " on " + tunnel.listenHost + ':' + clientPort);
        notifyEvent("openBrowserHTTPClientResult", "ok");
    }

    private class I2PTunnelFIFOQueue extends SimpleTimer2.TimedEvent {
        private final int PREGENERATED_LIMIT = 3;
        private LinkedList<I2PTunnelHTTPClient> clientPrecache = new LinkedList<I2PTunnelHTTPClient>();

        public I2PTunnelFIFOQueue() {
            super(_context.simpleTimer2());
            fillUpFIFOQueue();
        }

        public boolean fillUpFIFOQueue() {
            if (clientPrecache.size() < PREGENERATED_LIMIT) {
                for (int i = 0; i < clientPrecache.size(); i++) {
                    try {
                        final int port = findRandomOpenPort();
                        String hostname = "";
                        final I2PTunnelHTTPClient client = new I2PTunnelHTTPClient(
                                port, l, _ownDest, hostname, getEventDispatcher(), getTunnel());
                        clientPrecache.add(client);
                    } catch (IOException ioe) {
                        if (_log.shouldLog(Log.DEBUG))
                            _log.debug("Fatal error when pre-generating clients for performance", ioe);
                    }
                }
                return true;
            }
            return false;
        }

        public I2PTunnelHTTPClient poll() {
            return clientPrecache.poll();
        }

        public void destroy() {
            if (_log.shouldLog(Log.DEBUG))
                _log.debug("destroyinging I2PTunnelFIFOQueue: len == " + clientPrecache.size());
            for (int i = 0; i < clientPrecache.size(); i++) {
                I2PTunnelHTTPClient client = clientPrecache.poll();
                client.destroy();
            }
            if (_log.shouldLog(Log.DEBUG))
                _log.debug("I2PTunnelFIFOQueue destroyed: len == " + clientPrecache.size());
        }

        @Override
        public void timeReached() {
            fillUpFIFOQueue();
        }
    }

    /**
     * Actually start working on incoming connections.
     * Overridden to start an internal socket too.
     * Also instantiates the "OutProxy" I2PTunnelHTTPClient
     *
     * @since 0.9.62
     */
    @Override
    public void startRunning() {
        initialize();
        if (open) {
            this.isr = new InternalSocketRunner(this);
            this.isr.start();
            final int port = getLocalPort();
            _context.portMapper().register(PortMapper.SVC_HTTP_PROXY_TABBED,
                    getTunnel().listenHost, port);
            _context.portMapper().register(PortMapper.SVC_HTTPS_PROXY_TABBED,
                    getTunnel().listenHost, port);
        }
        try {
            final int port = findRandomOpenPort();
            Object proxyList = getHostMultiplexerProperties(Hash.FAKE_HASH.toBase32()).get("proxyList");
            String proxyListString = null;
            if (proxyList != null)
                proxyListString = proxyList.toString();
            final I2PTunnelHTTPClient client = new I2PTunnelHTTPClient(
                    port, l, _ownDest, proxyListString, getEventDispatcher(), getTunnel());
            client.getTunnel().setClientOptions(getHostMultiplexerProperties(Hash.FAKE_HASH.toBase32()));
            clients.put(Hash.FAKE_HASH, client);
        } catch (final IOException ioe) {
            if (_log.shouldLog(Log.DEBUG))
                _log.debug("Unable to find a random port");
        }
    }

    /**
     * Overridden to close internal socket too.
     * Also overridden to close the multiplexed proxies before closing the
     * I2PTunnelHTTPBrowserClient and remove them from the map.
     *
     * @since 0.9.62
     */
    @Override
    public boolean close(final boolean forced) {
        if (ffq != null) {
            ffq.cancel();
            ffq = null;
        }
        for (final Hash h : clients.keySet()) {
            unmapClient(h);
            clients.get(h).close(forced);
            clients.remove(h);
        }
        final int port = getLocalPort();
        int reg = _context.portMapper().getPort(PortMapper.SVC_HTTP_PROXY_TABBED);
        if (reg == port) {
            _context.portMapper().unregister(PortMapper.SVC_HTTP_PROXY_TABBED);
        }
        reg = _context.portMapper().getPort(PortMapper.SVC_HTTPS_PROXY_TABBED);
        if (reg == port) {
            _context.portMapper().unregister(PortMapper.SVC_HTTPS_PROXY_TABBED);
        }
        final boolean rv = super.close(forced);
        if (this.isr != null) {
            this.isr.stopRunning();
        }
        return rv;
    }

    /**
     * Get the I2PTunnelHTTPClient used for the uri parameter out of the multiplex.
     * Gets the host from the URI, and passes it to getI2PTunnelHTTPClient(hostname)
     *
     * @param uri a URI to discover an I2PTunnelHTTPClient for
     * @return the correct I2PTunnelHTTPClient
     * @since 0.9.62
     */
    public I2PTunnelHTTPClient getI2PTunnelHTTPClient(final URI uri) {
        if (uri == null)
            if (_log.shouldLog(Log.DEBUG))
                _log.debug("uri is null");
        final String hostname = uri.getHost();
        return getI2PTunnelHTTPClient(hostname);
    }

    /**
     * Looks up a hostname to convert it to a destination.
     * If a null destination is found, return the null client/Outproxy Client.
     * If a destination is found, convert it to a hash and look it up in the clients
     * map.
     * Return the result.
     *
     * @param hostname a hostname to convert to a destination hash
     * @return I2PTunnelHTTPClient for the host, or null if it's not created yet.
     * @since 0.9.62
     */
    public I2PTunnelHTTPClient getI2PTunnelHTTPClient(final String hostname) {
        if (hostname == null) {
            if (_log.shouldLog(Log.DEBUG))
                _log.debug("origin separator is null, returning outproxy client");
            return nullClient();
        }
        final Destination destination = _context.namingService().lookup(hostname);
        if (destination == null) {
            if (_log.shouldLog(Log.DEBUG))
                _log.debug("destination is null, getting outproxy client");
            return nullClient();
        }
        if (_log.shouldLog(Log.DEBUG))
            _log.debug("destination is: " + destination.getHash());
        return clients.get(destination.getHash());
    }

    /**
     * Create the default options (using the default timeout, etc).
     * Warning, this does not make a copy of I2PTunnel's client options,
     * it modifies them directly.
     * Do not use overrides for per-socket options.
     *
     * This will throw IAE on tunnel build failure
     *
     * @since 0.9.62
     */
    @Override
    protected I2PSocketOptions getDefaultOptions(final Properties overrides) {
        final Properties defaultOpts = getTunnel().getClientOptions();
        defaultOpts.putAll(overrides);
        if (!defaultOpts.contains(I2PSocketOptions.PROP_READ_TIMEOUT))
            defaultOpts.setProperty(I2PSocketOptions.PROP_READ_TIMEOUT, "" + I2PTunnelHTTPClient.DEFAULT_READ_TIMEOUT);
        if (!defaultOpts.contains("i2p.streaming.inactivityTimeout"))
            defaultOpts.setProperty("i2p.streaming.inactivityTimeout", "" + I2PTunnelHTTPClient.DEFAULT_READ_TIMEOUT);
        if (!defaultOpts.contains("inbound.quantity"))
            defaultOpts.setProperty("inbound.quantity", "" + I2PTunnelHTTPBrowserClient.INBOUND_DEFAULT_LENGTH);
        if (!defaultOpts.contains("outbound.quantity"))
            defaultOpts.setProperty("outbound.quantity", "" + I2PTunnelHTTPBrowserClient.OUTBOUND_DEFAULT_LENGTH);
        // delayed start
        verifySocketManager();
        final I2PSocketOptions opts = sockMgr.buildOptions(defaultOpts);
        if (!defaultOpts.containsKey(I2PSocketOptions.PROP_CONNECT_TIMEOUT)) {
            opts.setConnectTimeout(DEFAULT_CONNECT_TIMEOUT);
        }
        return opts;
    }

    /**
     * Given a uri:
     * - Extract a hostname, discover a destination, then convert to a hash
     * - Check whether an I2PTunnelHTTPClient exists for that hash in clients
     * - If not, create one
     *
     * @param uri
     * @return true only if a new I2PTunnelHTTPClient was created
     * @since 0.9.62
     */
    protected boolean mapNewClient(final URI uri) {
        final String hostname = uri.getHost();
        if (hostname == null)
            return false;
        final Destination destination = _context.namingService().lookup(hostname);
        if (destination == null) {
            return false;
        }
        if (getI2PTunnelHTTPClient(uri) != null)
            return false;
        if (_log.shouldLog(Log.DEBUG))
            _log.debug("Mapping new HTTP client for destination:" + uri.getHost() + "/" + destination.toBase32());
        I2PTunnelHTTPClient client = ffq.poll();
        clients.put(destination.getHash(), client);
        getI2PTunnelHTTPClient(hostname).getTunnel()
                .setClientOptions(getHostMultiplexerProperties(destination.toBase32()));
        getI2PTunnelHTTPClient(hostname).startRunning();
        mapPort(destination.getHash(), client.getLocalPort());
        return true;
    }

    /**
     * unmap an existing client by hash, which will unregister it's port from the
     * port mapper
     *
     * @param hash
     * @return true if the client existed and was unmapped
     * @since 0.9.62
     */
    protected boolean unmapClient(final Hash hash) {
        if (clients.get(hash) != null) {
            if (_log.shouldLog(Log.DEBUG))
                _log.debug("Unmapping and shutting down HTTP client for desintation: " + hash);
            unmapPort(hash);
            return true;
        }
        return false;
    }

    /**
     *
     */
    protected Properties getHostMultiplexerProperties(String identifier) {
        Properties opts = getTunnel().getClientOptions();
        if (opts == null)
            opts = new Properties();
        opts.remove("i2cp.leaseSetPrivateKey");
        opts.remove("inbound.randomKey");
        opts.remove("outbound.randomKey");
        String inNick = opts.getProperty("inbound.nickname", "TABBED_PROXY");
        String outNick = opts.getProperty("outbound.nickname", "TABBED_PROXY");
        opts.remove("inbound.nickname");
        opts.remove("outbound.nickname");
        opts.setProperty("inbound.nickname", inNick + "@" + identifier);
        opts.setProperty("outbound.nickname", outNick + "@" + identifier);
        if (_log.shouldLog(Log.DEBUG))
            _log.debug("Options: " + opts.toString());
        return opts;
    }

    /**
     * Variant clientConnectionRun based on the one in I2PTunnelHTTPClient, modified
     * to read the entire request and annotate it advance, then look up an
     * additional proxy from the clients multiplex to forward it to.
     *
     * @since 0.9.62
     */
    @Override
    protected void clientConnectionRun(final Socket s) {
        OutputStream out = null;

        // in-net outproxy
        boolean usingWWWProxy = false;

        final long requestId = __requestId.incrementAndGet();
        I2PSocket i2ps = null;
        String targetRequest = null;
        String currentProxy = null;
        I2PTunnelHTTPClient httpClient = null;
        try {
            int requestCount = 0;
            s.setSoTimeout(I2PTunnelHTTPClientBase.INITIAL_SO_TIMEOUT);
            out = s.getOutputStream();
            final InputReader reader = new InputReader(s.getInputStream());
            final HTTPRequestReader hrr = new HTTPRequestReader(s, _context, reader, __requestId,
                    I2PTunnelHTTPClientBase.BROWSER_READ_TIMEOUT, getTunnel(), nullClient());
            if (_log.shouldLog(Log.DEBUG))
                _log.debug("clientConnectionRun on Tab-Aware Proxy to" + hrr.toString());
            if (hrr.originSeparator() == null) {
                if (_log.shouldLog(Log.WARN))
                    _log.warn("Invalid URL used as origin in tab-aware proxy");
                return;
            }
            usingWWWProxy = hrr.getUsingWWWProxy();
            if (mapNewClient(hrr.originSeparator())) {
                if (_log.shouldLog(Log.DEBUG))
                    _log.debug("Set up a new tab-aware proxy for: " + hrr.originSeparator());
            } else {
                if (_log.shouldLog(Log.DEBUG))
                    _log.debug("A tab-aware proxy for: " + hrr.originSeparator() + "already existed. Re-using it.");
            }
            targetRequest = hrr.getTargetRequest();
            if (_log.shouldLog(Log.DEBUG))
                _log.debug("Target Request is: " + targetRequest);
            currentProxy = hrr.getCurrentProxy();
            if (_log.shouldLog(Log.DEBUG))
                _log.debug("Current Proxy is: " + currentProxy);
            httpClient = getI2PTunnelHTTPClient(hrr.originSeparator());
            if (httpClient == null) {
                if (_log.shouldLog(Log.ERROR))
                    _log.error("Proxy is not available for destination");
                return;
            }
            if (_log.shouldLog(Log.DEBUG))
                _log.debug("Locally-isolated destination for:" + hrr.originSeparator().getHost() + " is on: "
                        + httpClient.getLocalPort());

            /*
             * final boolean keepalive =
             * getBooleanOption(I2PTunnelHTTPClient.OPT_KEEPALIVE_BROWSER,
             * DEFAULT_KEEPALIVE_BROWSER)
             * &&
             * !(s instanceof InternalSocket);
             */
            do {
                if (hrr.getNewRequest().length() > 0 && _log.shouldDebug())
                    _log.debug(httpClient.getPrefix(requestId) + "hrr.getNewRequest() header: [" + hrr.getNewRequest()
                            + ']');

                if (hrr.getMethod() == null || (hrr.getDestination() == null && !hrr.getUsingInternalOutproxy())) {
                    if (requestCount > 0) {
                        // SocketTimeout, normal to get here for persistent connections,
                        // because DataHelper.readLine() returns null on EOF
                        return;
                    }
                    _log.debug("No HTTP hrr.getMethod() found in the request.");
                    try {
                        if (hrr.getProtocol() != null && "http".equals(hrr.getProtocol().toLowerCase(Locale.US))) {
                            out.write(httpClient.getErrorPage("denied", I2PTunnelHTTPClient.ERR_REQUEST_DENIED)
                                    .getBytes("UTF-8"));
                        } else {
                            out.write(httpClient.getErrorPage("protocol", I2PTunnelHTTPClient.ERR_BAD_PROTOCOL)
                                    .getBytes("UTF-8"));
                        }
                        I2PTunnelHTTPClientBase.writeFooter(out);
                    } catch (final IOException ioe) {
                        // ignore
                    }
                    return;
                }

                if (_log.shouldLog(Log.DEBUG)) {
                    _log.debug(httpClient.getPrefix(requestId) + "Destination: " + hrr.getDestination());
                }

                // Authorization
                // Yes, this is sent and checked for every request on a persistent connection
                final AuthResult result = authorize(s, requestId, hrr.getMethod(), hrr.getAuthorization());
                if (result != AuthResult.AUTH_GOOD) {
                    if (_log.shouldLog(Log.WARN)) {
                        if (hrr.getAuthorization() != null) {
                            _log.warn(getPrefix(requestId) + "Auth failed, sending 407 again");
                        } else {
                            _log.warn(getPrefix(requestId) + "Auth required, sending 407");
                        }
                    }
                    try {
                        out.write(getAuthError(result == AuthResult.AUTH_STALE).getBytes("UTF-8"));
                        I2PTunnelHTTPClientBase.writeFooter(out);
                    } catch (final IOException ioe) {
                        // ignore
                    }
                    return;
                }

                // Serve local proxy files (images, css linked from error pages)
                // Ignore all the headers
                if (hrr.getUsingInternalServer()) {
                    try {
                        // disable the add form if address helper is disabled
                        if (hrr.getInternalPath().equals("/add") &&
                                Boolean.parseBoolean(getTunnel().getClientOptions()
                                        .getProperty(I2PTunnelHTTPClient.PROP_DISABLE_HELPER))) {
                            out.write(I2PTunnelHTTPClient.ERR_HELPER_DISABLED.getBytes("UTF-8"));
                        } else {
                            LocalHTTPServer.serveLocalFile(httpClient.getContext(), httpClient.sockMgr, out,
                                    hrr.getMethod(),
                                    hrr.getInternalPath(),
                                    hrr.getInternalRawQuery(), httpClient._proxyNonce, hrr.getAllowGzip());
                        }
                    } catch (final IOException ioe) {
                        // ignore
                    }
                    return;
                }

                // no destination, going to outproxy plugin
                if (hrr.getUsingInternalOutproxy()) {
                    final Socket outSocket = hrr.getOutproxy().connect(hrr.getHost(), hrr.getRemotePort());
                    final OnTimeout onTimeout = new OnTimeout(s, s.getOutputStream(), hrr.getTargetRequest(),
                            hrr.getUsingWWWProxy(),
                            hrr.getCurrentProxy(), requestId);
                    byte[] data;
                    byte[] response;
                    if (hrr.getIsConnect()) {
                        data = null;
                        response = I2PTunnelHTTPClientBase.SUCCESS_RESPONSE.getBytes("UTF-8");
                    } else {
                        data = hrr.getNewRequest().toString().getBytes("ISO-8859-1");
                        response = null;
                    }
                    final Thread t = new I2PTunnelOutproxyRunner(s, outSocket, httpClient.sockLock, data, response,
                            onTimeout);
                    // we are called from an unlimited thread pool, so run inline
                    // t.start();
                    t.run();
                    return;
                }

                // LOOKUP
                // If the host is "i2p", the getHostName() lookup failed, don't try to
                // look it up again as the naming service does not do negative caching
                // so it will be slow.
                Destination clientDest = null;
                final String addressHelper = httpClient.addressHelpers.get(hrr.getDestination().toLowerCase(Locale.US));
                if (addressHelper != null) {
                    clientDest = httpClient.getContext().namingService().lookup(addressHelper);
                    if (clientDest == null) {
                        // remove bad entries
                        httpClient.addressHelpers.remove(hrr.getDestination().toLowerCase(Locale.US));
                        if (_log.shouldLog(Log.WARN)) {
                            _log.warn(httpClient.getPrefix(requestId) + "Could not find destination for "
                                    + addressHelper);
                        }
                        final String header = httpClient.getErrorPage("ahelper-notfound",
                                I2PTunnelHTTPClient.ERR_AHELPER_NOTFOUND);
                        try {
                            httpClient.writeErrorMessage(header, out, hrr.getTargetRequest(), false,
                                    hrr.getDestination());
                        } catch (final IOException ioe) {
                            // ignore
                        }
                        return;
                    }
                } else if ("i2p".equals(hrr.getHost())) {
                    clientDest = null;
                } else if (hrr.getDestination().toLowerCase(Locale.US).endsWith(".b32.i2p")) {
                    final int len = hrr.getDestination().length();
                    if (len < 60 || (len >= 61 && len <= 63)) {
                        // 8-59 or 61-63 chars, this won't work
                        final String header = httpClient.getErrorPage("b32",
                                I2PTunnelHTTPClientBase.ERR_DESTINATION_UNKNOWN);
                        try {
                            httpClient.writeErrorMessage(header, httpClient._t("Corrupt Base32 address"), out,
                                    hrr.getTargetRequest(), false,
                                    hrr.getDestination());
                        } catch (final IOException ioe) {
                        }
                        return;
                    }
                    if (len >= 64) {
                        // catch b33 errors before session lookup
                        try {
                            final BlindData bd = Blinding.decode(httpClient.getContext(), hrr.getDestination());
                            if (_log.shouldWarn())
                                _log.warn("Resolved b33 " + bd);
                            // TESTING
                            // sess.sendBlindingInfo(bd, 24*60*60*1000);
                        } catch (final IllegalArgumentException iae) {
                            if (_log.shouldWarn())
                                _log.warn("Unable to resolve b33 " + hrr.getDestination(), iae);
                            // b33 error page
                            final String header = httpClient.getErrorPage("b32",
                                    I2PTunnelHTTPClientBase.ERR_DESTINATION_UNKNOWN);
                            try {
                                httpClient.writeErrorMessage(header, iae.getMessage(), out, hrr.getTargetRequest(),
                                        false,
                                        hrr.getDestination());
                            } catch (final IOException ioe) {
                            }
                            return;
                        }
                    }
                    // use existing session to look up for efficiency
                    httpClient.verifySocketManager();
                    final I2PSession sess = httpClient.sockMgr.getSession();
                    if (!sess.isClosed()) {
                        if (len == 60) {
                            final byte[] hData = Base32.decode(hrr.getDestination().substring(0, 52));
                            if (hData != null) {
                                if (_log.shouldInfo())
                                    _log.info("lookup b32 in-session " + hrr.getDestination());
                                final Hash hash = Hash.create(hData);
                                clientDest = sess.lookupDest(hash, 20 * 1000);
                            } else {
                                clientDest = null;
                            }
                        } else if (len >= 64) {
                            if (_log.shouldInfo())
                                _log.info("lookup b33 in-session " + hrr.getDestination());
                            final LookupResult lresult = sess.lookupDest2(hrr.getDestination(), 20 * 1000);
                            clientDest = lresult.getDestination();
                            final int code = lresult.getResultCode();
                            if (code != LookupResult.RESULT_SUCCESS) {
                                if (_log.shouldWarn())
                                    _log.warn("Unable to resolve b33 " + hrr.getDestination() + " error code " + code);
                                if (code != LookupResult.RESULT_FAILURE) {
                                    // form to supply missing data
                                    httpClient.writeB32SaveForm(out, hrr.getDestination(), code,
                                            hrr.getTargetRequest());
                                    return;
                                }
                                // fall through to standard destination unreachable error page
                            }
                        }
                    } else {
                        if (_log.shouldInfo())
                            _log.info("lookup b32 out of session " + hrr.getDestination());
                        // TODO can't get result code from here
                        clientDest = httpClient.getContext().namingService().lookup(hrr.getDestination());
                    }
                } else {
                    if (_log.shouldInfo())
                        _log.info("lookup hostname " + hrr.getDestination());
                    clientDest = httpClient.getContext().namingService().lookup(hrr.getDestination());
                }

                if (clientDest == null) {
                    // l.log("Could not resolve " + destination + ".");
                    if (_log.shouldLog(Log.WARN)) {
                        _log.warn("Unable to resolve " + hrr.getDestination() + " (proxy? " + hrr.getUsingWWWProxy()
                                + ", request: "
                                + hrr.getTargetRequest());
                    }
                    String header;
                    String jumpServers = null;
                    String extraMessage = null;
                    if (hrr.getUsingWWWProxy()) {
                        header = httpClient.getErrorPage("dnfp", I2PTunnelHTTPClientBase.ERR_DESTINATION_UNKNOWN);
                    } else if (hrr.getAhelperPresent()) {
                        header = httpClient.getErrorPage("dnfb", I2PTunnelHTTPClientBase.ERR_DESTINATION_UNKNOWN);
                    } else if (hrr.getDestination().length() >= 60
                            && hrr.getDestination().toLowerCase(Locale.US).endsWith(".b32.i2p")) {
                        header = httpClient.getErrorPage("nols", I2PTunnelHTTPClientBase.ERR_DESTINATION_UNKNOWN);
                        extraMessage = httpClient._t("Destination lease set not found");
                    } else {
                        header = httpClient.getErrorPage("dnfh", I2PTunnelHTTPClientBase.ERR_DESTINATION_UNKNOWN);
                        jumpServers = getTunnel().getClientOptions().getProperty(I2PTunnelHTTPClient.PROP_JUMP_SERVERS);
                        if (jumpServers == null) {
                            jumpServers = I2PTunnelHTTPClient.DEFAULT_JUMP_SERVERS;
                        }
                        final int jumpDelay = 400 + httpClient.getContext().random().nextInt(256);
                        try {
                            Thread.sleep(jumpDelay);
                        } catch (final InterruptedException ie) {
                        }
                    }
                    try {
                        httpClient.writeErrorMessage(header, extraMessage, out, hrr.getTargetRequest(),
                                hrr.getUsingWWWProxy(),
                                hrr.getDestination(),
                                jumpServers);
                    } catch (final IOException ioe) {
                        // ignore
                    }
                    return;
                }

                // as of 0.9.35, allowInternalSSL defaults to true, and overridden to true
                // unless PROP_SSL_SET is set
                if (hrr.getIsConnect() &&
                        !hrr.getUsingWWWProxy() &&
                        getTunnel().getClientOptions().getProperty(I2PTunnelHTTPClient.PROP_SSL_SET) != null &&
                        !Boolean.parseBoolean(getTunnel().getClientOptions()
                                .getProperty(I2PTunnelHTTPClient.PROP_INTERNAL_SSL, "true"))) {
                    try {
                        httpClient.writeErrorMessage(I2PTunnelHTTPClient.ERR_INTERNAL_SSL, out, hrr.getTargetRequest(),
                                false, hrr.getDestination());
                    } catch (final IOException ioe) {
                        // ignore
                    }
                    if (_log.shouldLog(Log.WARN))
                        _log.warn("SSL to i2p destinations denied by configuration: " + hrr.getTargetRequest());
                    return;
                }

                // Address helper response form
                // This will only load once - the second time it won't be "new"
                // Don't do this for eepget, which uses a user-agent of "Wget"
                if (hrr.getAhelperNew() && "GET".equals(hrr.getMethod()) &&
                        (hrr.getUserAgent() == null || !hrr.getUserAgent().startsWith("Wget")) &&
                        !Boolean.parseBoolean(
                                getTunnel().getClientOptions().getProperty(I2PTunnelHTTPClient.PROP_DISABLE_HELPER))) {
                    try {
                        httpClient.writeHelperSaveForm(out, hrr.getDestination(), hrr.getAhelperKey(),
                                hrr.getTargetRequest(),
                                hrr.getReferer());
                    } catch (final IOException ioe) {
                        // ignore
                    }
                    return;
                }

                // Redirect to non-addresshelper URL to not clog the browser address bar
                // and not pass the parameter to the I2P Site.
                // This also prevents the not-found error page from looking bad
                // Syndie can't handle a redirect of a POST
                if (hrr.getAhelperPresent() && !"POST".equals(hrr.getMethod()) && !"PUT".equals(hrr.getMethod())) {
                    final String uri = hrr.getTargetRequest();
                    if (_log.shouldLog(Log.DEBUG)) {
                        _log.debug("Auto redirecting to " + uri);
                    }
                    try {
                        out.write(("HTTP/1.1 301 Address Helper Accepted\r\n" +
                                "Location: " + uri + "\r\n" +
                                "Connection: close\r\n" +
                                "\r\n").getBytes("UTF-8"));
                    } catch (final IOException ioe) {
                        // ignore
                    }
                    return;
                }

                // Close persistent I2PSocket if destination or port changes
                // and open a new one.
                // We do not maintain a pool of open I2PSockets or look for
                // an available one. Keep it very simple.
                // As long as the traffic keeps going to the same place
                // we will keep reusing it.
                // While we should be able to reuse it if only the port changes,
                // that should be extremely rare, so don't bother.
                // For common use patterns including outproxy use,
                // this should still be quite effective.
                if (i2ps == null || i2ps.isClosed() ||
                        hrr.getRemotePort() != i2ps.getPort() ||
                        !clientDest.equals(i2ps.getPeerDestination())) {
                    if (i2ps != null) {
                        if (_log.shouldInfo())
                            _log.info("Old socket closed or different dest/port, opening new one");
                        try {
                            i2ps.close();
                        } catch (final IOException ioe) {
                        }
                    }
                    final Properties opts = getHostMultiplexerProperties(hrr.originSeparator().getHost());// new
                                                                                                          // Properties();
                    // opts.setProperty("i2p.streaming.inactivityTimeout", ""+120*1000);
                    // 1 == disconnect. see ConnectionOptions in the new streaming lib, which i
                    // dont want to hard link to here
                    // opts.setProperty("i2p.streaming.inactivityTimeoutAction", ""+1);
                    I2PSocketOptions sktOpts;
                    try {
                        sktOpts = getDefaultOptions(opts);
                    } catch (final RuntimeException re) {
                        // tunnel build failure
                        final StringBuilder buf = new StringBuilder(128);
                        buf.append("HTTP/1.1 503 Service Unavailable");
                        if (re.getMessage() != null)
                            buf.append(" - ").append(re.getMessage());
                        buf.append("\r\n\r\n");
                        try {
                            out.write(buf.toString().getBytes("UTF-8"));
                        } catch (final IOException ioe) {
                        }
                        throw re;
                    }
                    if (hrr.getRemotePort() > 0)
                        sktOpts.setPort(hrr.getRemotePort());
                    i2ps = httpClient.createI2PSocket(clientDest, sktOpts);
                }

                I2PTunnelRunner t;
                I2PTunnelHTTPClientRunner hrunner = null;
                if (hrr.getIsConnect()) {
                    byte[] data;
                    byte[] response;
                    if (hrr.getUsingWWWProxy()) {
                        data = hrr.getNewRequest().toString().getBytes("ISO-8859-1");
                        response = null;
                    } else {
                        data = null;
                        response = I2PTunnelHTTPClientBase.SUCCESS_RESPONSE.getBytes("UTF-8");
                    }
                    // no OnTimeout, we can't send HTTP error responses after sending
                    // SUCCESS_RESPONSE.
                    t = new I2PTunnelRunner(s, i2ps, httpClient.sockLock, data, response, mySockets, (OnTimeout) null);
                } else {
                    final byte[] data = hrr.getNewRequest().toString().getBytes("ISO-8859-1");
                    final OnTimeout onTimeout = new OnTimeout(s, s.getOutputStream(), hrr.getTargetRequest(),
                            hrr.getUsingWWWProxy(),
                            hrr.getCurrentProxy(), requestId, hrr.getHostLowerCase(), hrr.getIsConnect());
                    final boolean keepaliveI2P = hrr.getKeepAliveI2P()
                            && getBooleanOption(I2PTunnelHTTPClient.OPT_KEEPALIVE_I2P,
                                    I2PTunnelHTTPClient.DEFAULT_KEEPALIVE_I2P);
                    hrunner = new I2PTunnelHTTPClientRunner(s, i2ps, httpClient.sockLock, data, mySockets, onTimeout,
                            keepaliveI2P, hrr.getKeepAliveI2P(), hrr.getIsHead());
                    t = hrunner;
                }
                if (hrr.getUsingWWWProxy()) {
                    t.setSuccessCallback(
                            new OnProxySuccess(hrr.getCurrentProxy(), hrr.getHostLowerCase(), hrr.getIsConnect()));
                }
                // we are called from an unlimited thread pool, so run inline
                // t.start();
                t.run();

                // I2PTunnelHTTPClientRunner spins off the browser-to-i2p thread and keeps
                // the i2p-to-socket copier in-line. So we won't get here until the i2p socket
                // is closed.
                // check if whatever was in the response does not allow keepalive
                if (hrr.getKeepAliveI2P() && hrunner != null && !hrunner.getKeepAliveSocket())
                    break;
                // The old I2P socket was closed, null it out so we'll get a new one
                // next time around
                if (hrunner != null && !hrunner.getKeepAliveI2P())
                    i2ps = null;
                // go around again
                requestCount++;
            } while (hrr.getKeepAliveI2P());

        } catch (final IOException ex) {
            // This is normal for keepalive when the browser closed the socket,
            // or a SocketTimeoutException if we gave up first
            if (_log.shouldLog(Log.INFO)) {
                _log.info(httpClient.getPrefix(requestId) + "Error trying to connect", ex);
            }

            httpClient.handleClientException(ex, out, targetRequest, usingWWWProxy, currentProxy,
                    requestId);
        } catch (final I2PException ex) {
            if (_log.shouldLog(Log.INFO)) {
                _log.info(httpClient.getPrefix(requestId) + "Error trying to connect",
                        ex);
            }
            httpClient.handleClientException(ex, out, targetRequest, usingWWWProxy,
                    currentProxy, requestId);
        } catch (final OutOfMemoryError oom) {
            final IOException ex = new IOException("OOM");
            _log.error(httpClient.getPrefix(requestId) + "Error trying to connect", oom);
            httpClient.handleClientException(ex, out, targetRequest, usingWWWProxy,
                    currentProxy, requestId);
        } finally {
            // only because we are running it inline
            I2PTunnelHTTPClientBase.closeSocket(s);
            if (i2ps != null)
                try {
                    i2ps.close();
                } catch (final IOException ioe) {
                }
        }
    }

    /**
     * @return "I2P Browser Proxy"
     * @since 0.9.62
     */
    protected String getRealm() {
        return AUTH_REALM;
    }

    /**
     * Get the client indexed by the Hash.FAKE_HASH value, which is used for all
     * outproxy-bound requests.
     * Returns the I2PTunnelHTTPClient associated with the FAKE_HASH from the
     * clients HashMap.
     *
     * @return I2PTunnelHTTPClient used for outproxy requests.
     * @since 0.9.62
     */
    private I2PTunnelHTTPClient nullClient() {
        if (clients.get(Hash.FAKE_HASH) == null) {
            if (_log.shouldLog(Log.ERROR))
                _log.error("null client for outproxy request not found");
        } else {
            if (_log.shouldLog(Log.DEBUG))
                _log.debug("Getting null client for outproxy request");
        }
        return clients.get(Hash.FAKE_HASH);
    }

    /**
     * Registers a multiplexed I2PTunnelHTTPClient's port with the PortMapper.
     * Uses @hash.toBase32() as a suffix to distinguish the proxy from other members
     * of the multiplex.
     *
     * @param hostname
     * @param port
     * @since 0.9.62
     */
    private void mapPort(final Hash hash, final int port) {
        _context.portMapper().register(PortMapper.SVC_HTTP_PROXY_TABBED + "@" +
                hash.toBase32(),
                getTunnel().listenHost, port);
        _context.portMapper().register(PortMapper.SVC_HTTPS_PROXY_TABBED + "@" +
                hash.toBase32(),
                getTunnel().listenHost, port);
    }

    /**
     * Unregisters a multiplexed I2PTunnelHTTPClient's port from the PortMapper
     * using the hash.toBase32() to identify it.
     *
     * @since 0.9.62
     */
    private void unmapPort(final Hash hash) {
        _context.portMapper().unregister(PortMapper.SVC_HTTP_PROXY_TABBED + "@" +
                hash.toBase32());
        _context.portMapper().unregister(PortMapper.SVC_HTTPS_PROXY_TABBED + "@" +
                hash.toBase32());
    }

    /**
     * Find an open port from the default range selected by Java by:
     * opening a socket on a random port in the scope of the function
     * returning the value of the automatically chosen port.
     * closing the socket which dies at the end of the function.
     *
     * @return int a random number in Java's default random port range.
     * @since 0.9.62
     */
    private static int findRandomOpenPort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0);) {
            return socket.getLocalPort();
        }
    }
}
