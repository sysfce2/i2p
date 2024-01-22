package net.i2p.router.update;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.IllegalArgumentException;
import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

import net.i2p.CoreVersion;
import net.i2p.crypto.SU3File;
import net.i2p.crypto.TrustedUpdate;
import net.i2p.data.DataFormatException;
import net.i2p.data.DataHelper;
import net.i2p.data.SigningPublicKey;
import net.i2p.router.RouterContext;
import net.i2p.router.web.ConfigUpdateHandler;
import net.i2p.router.web.Messages;
import net.i2p.router.web.PluginStarter;
import net.i2p.router.web.RouterConsoleRunner;
import net.i2p.update.*;
import net.i2p.util.EepGet;
import net.i2p.util.FileUtil;
import net.i2p.util.Log;
import net.i2p.util.OrderedProperties;
import net.i2p.util.PortMapper;
import net.i2p.util.SecureDirectory;
import net.i2p.util.SecureFile;
import net.i2p.util.SystemVersion;
import net.i2p.util.VersionComparator;
import org.klomp.snark.I2PSnarkUtil;
import org.klomp.snark.MetaInfo;
import org.klomp.snark.Snark;
import org.klomp.snark.SnarkManager;

/**
 * Check for an updated version of a plugin.
 * A plugin is a standard .sud file with a 40-byte signature,
 * a 16-byte version, and a .zip file.
 *
 * So we get the current version and update URL for the installed plugin,
 * then fetch the first 56 bytes of the URL, extract the version,
 * and compare.
 *
 * uri list must not be empty.
 *
 * Moved from web/ and turned into an UpdateTask.
 *
 * @since 0.9.4 moved from PluginUpdateHandler
 */
class PluginUpdateTorrentRunner extends PluginUpdateRunner {

    /*
     * private String _appName;
     * private final String _appDisplayName;
     * private final String _oldVersion;
     * private final URI _uri;
     * private final String _xpi2pURL;
     * private boolean _updated;
     */
    private String _errMsg = "";

    private static final String XPI2P = "app.xpi2p";
    private static final String ZIP = XPI2P + ".zip";
    public static final String PLUGIN_DIR = PluginStarter.PLUGIN_DIR;
    private static final String PROP_ALLOW_NEW_KEYS = "routerconsole.allowUntrustedPlugins";

    public PluginUpdateTorrentRunner(RouterContext ctx, ConsoleUpdateManager mgr, List<URI> uris,
            String appName, String oldVersion) {
        super(ctx, mgr, uris, appName, oldVersion);
    }

    @Override
    protected void update() {
        _updated = false;
        if (_xpi2pURL.startsWith("file:") || _method == UpdateMethod.FILE) {
            super.update();
            return;
        } else {
            if (_xpi2pURL.endsWith(".torrent")) {
                updateStatus("<b>" + _t("Downloading plugin from {0}", _xpi2pURL) + "</b>");
                try {
                    _get = new EepGet(_context, 1, _updateFile, _xpi2pURL, false);
                    _get.fetch(CONNECT_TIMEOUT, -1, true ? INACTIVITY_TIMEOUT : NOPROXY_INACTIVITY_TIMEOUT);
                    File uf = new File(_updateFile);
                    if (uf.exists()) {
                        FileInputStream fis = new FileInputStream(uf);
                        MetaInfo torrent = new MetaInfo(fis);
                        fis.close();
                        byte[] ih = torrent.getInfoHash();
                        // do we already have it?
                        SnarkManager _smgr = new SnarkManager(_context);
                        Snark snark = _smgr.getTorrentByInfoHash(ih);
                        /*if (_snark != null) {
                            if (_snark.getMetaInfo() != null) {
                                 _hasMetaInfo = true;
                                 Storage storage = _snark.getStorage();
                                 if (storage != null && storage.complete())
                                     processComplete(_snark);
                            }
                            if (!_isComplete) {
                                if (_snark.isStopped() && !_snark.isStarting())
                                    _snark.startTorrent();
                                // we aren't a listener so we must poll
                                new Watcher();
                            }
                            break;
                        }*/
                        /*String name = torrent.getName();
                        String trackerURL = torrent.getTrackerURL();
                        if (trackerURL == null && !_smgr.util().shouldUseDHT() &&
                            !_smgr.util().shouldUseOpenTrackers()) {
                            // but won't we use OT as a failsafe even if disabled?
                            _umgr.notifyAttemptFailed(this, "No tracker, no DHT, no OT", null);
                            continue;
                        }
                        _snark = _smgr.addMagnet(name, ih, trackerURL, true, true, null, this);
                        if (_snark != null) {
                            updateStatus("<b>" + _smgr.util().getString("Updating from {0}", linkify(updateURL)) + "</b>");
                            new Timeout();
                            break;
                        }*/
                    }
                } catch (Throwable t) {
                    _log.error("Error downloading plugin", t);
                }
            } else {
                super.update();
                return;
            }
        }
        if (_updated) {
            _mgr.notifyComplete(this, _newVersion, null);
            _mgr.notifyComplete(this, _errMsg);
        } else {
            _mgr.notifyTaskFailed(this, _errMsg, null);
        }
    }

    /**
     * Overridden to change the "Updating I2P" text in super
     * 
     * @since 0.9.35
     */
    @Override
    public void bytesTransferred(long alreadyTransferred, int currentWrite, long bytesTransferred, long bytesRemaining,
            String url) {
        long d = currentWrite + bytesTransferred;
        String status = "<b>" + _t("Downloading plugin") + ": " + _appDisplayName + "</b>";
        _mgr.notifyProgress(this, status, d, d + bytesRemaining);
    }

    @Override
    public void transferComplete(long alreadyTransferred, long bytesTransferred, long bytesRemaining, String url,
            String outputFile, boolean notModified) {
        if (!(_xpi2pURL.startsWith("file:") || _method == UpdateMethod.FILE))
            updateStatus("<b>" + _t("Plugin downloaded") + ": " + _appDisplayName + "</b>");
        File f = new File(_updateFile);
        File appDir = new SecureDirectory(_context.getConfigDir(), PLUGIN_DIR);
        if ((!appDir.exists()) && (!appDir.mkdir())) {
            f.delete();
            statusDone("<b>" + _t("Cannot create plugin directory {0}", appDir.getAbsolutePath()) + "</b>");
            return;
        }
        boolean isSU3;
        try {
            isSU3 = isSU3File(f);
        } catch (IOException ioe) {
            f.delete();
            statusDone("<b>" + ioe + "</b>");
            return;
        }
        if (isSU3)
            processSU3(f, appDir, url);
        else
            processSUD(f, appDir, url);
    }

    private void statusDone(String msg) {
        // if we fail, we will pass this back in notifyTaskFailed()
        _errMsg = msg;
        updateStatus(msg);
    }

}
