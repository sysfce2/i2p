package net.i2p.router.update;

import java.io.File;
import java.net.URI;
import java.util.List;

import net.i2p.crypto.TrustedUpdate;
import net.i2p.router.RouterContext;
import net.i2p.router.web.ConfigUpdateHandler;
import net.i2p.update.UpdateMethod;
import net.i2p.update.UpdateType;
import net.i2p.util.EepGet;
import net.i2p.util.PartialEepGet;
import net.i2p.util.PortMapper;

public class PluginUpdateTorrentChecker extends PluginUpdateChecker {
    private final String _appName;
    private final String _oldVersion;
    private final URI _torrentURI;

    public PluginUpdateTorrentChecker(RouterContext ctx, ConsoleUpdateManager mgr,
            List<URI> uris, String appName, String oldVersion) {
        //super(ctx, mgr, UpdateType.PLUGIN, uris, oldVersion);
        super(ctx, mgr, uris, appName, oldVersion);
        if (!uris.isEmpty())
            _currentURI = uris.get(0);
        if (uris.size() == 2)
            _torrentURI = uris.get(1);
        else
            _torrentURI = null;
        _appName = appName;
        _oldVersion = oldVersion;
    }

    @Override
    public void update() {
        boolean httpSeed = updateCheck(_currentURI.toString(), false);
        // use the HTTP-only check to determine if there's an update available using
        // PartialEepGet
        if (httpSeed) {
            // Here we know there is an update, but we don't know if there's a torrent update
            boolean torrentSeed = updateCheck(_torrentURI.toString(), true);
            if (!torrentSeed) {
                // No torrent update available, just use the HTTP update
                super.update();
            } else {
                // There's a torrent update available
                _mgr.notifyCheckComplete(this, true, true);
            }
        } else {
            // HTTP-only update check failed, we know nothing(special)
            _mgr.notifyCheckComplete(this, false, false);
        }
    }

    protected boolean updateCheck(String uriString, boolean torrent) {
        if (_torrentURI != null)
            return false;
        _isPartial = torrent;
        // performs exactly the same update check as PluginUpdateChecker
        // but returns a boolean value
        String proxyHost = _context.getProperty(ConfigUpdateHandler.PROP_PROXY_HOST,
                ConfigUpdateHandler.DEFAULT_PROXY_HOST);
        int proxyPort = ConfigUpdateHandler.proxyPort(_context);
        if (proxyPort == ConfigUpdateHandler.DEFAULT_PROXY_PORT_INT &&
                proxyHost.equals(ConfigUpdateHandler.DEFAULT_PROXY_HOST) &&
                _context.portMapper().getPort(PortMapper.SVC_HTTP_PROXY) < 0) {
            String msg = _t("HTTP client proxy tunnel must be running");
            if (_log.shouldWarn())
                _log.warn(msg);
            updateStatus("<b>" + msg + "</b>");
            return false;
        }
        updateStatus("<b>" + _t("Checking for update of plugin {0}", _appName) + "</b>");
        _baos.reset();
        try {
            if (_isPartial)
                _get = new PartialEepGet(_context, proxyHost, proxyPort, _baos, uriString, TrustedUpdate.HEADER_BYTES);
            else
                _get = new EepGet(_context, true, proxyHost, proxyPort,
                0, 0, 0, null, _baos,
                uriString, false, null, null);
            if (torrent)
                _get.addStatusListener(this);
            return _get.fetch(CONNECT_TIMEOUT);
        } catch (Throwable t) {
            _log.error("Error checking update for plugin", t);
        }
        return false;
    }
}
