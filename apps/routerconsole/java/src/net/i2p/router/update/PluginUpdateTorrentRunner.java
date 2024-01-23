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
import net.i2p.client.streaming.I2PSocketManager;
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
import net.i2p.util.SimpleTimer2;
import net.i2p.util.SystemVersion;
import net.i2p.util.VersionComparator;

import org.klomp.snark.BandwidthListener;
import org.klomp.snark.BitField;
import org.klomp.snark.CompleteListener;
import org.klomp.snark.I2PSnarkUtil;
import org.klomp.snark.MagnetURI;
import org.klomp.snark.MetaInfo;
import org.klomp.snark.Snark;
import org.klomp.snark.SnarkManager;
import org.klomp.snark.Storage;
import org.klomp.snark.comments.CommentSet;

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
class PluginUpdateTorrentRunner extends PluginUpdateRunner implements CompleteListener {

    private static final long MAX_LENGTH = 128 * 1024 * 1024;
    private static final long METAINFO_TIMEOUT = 60 * 60 * 1000;
    private static final long COMPLETE_TIMEOUT = 12 * 60 * 60 * 1000;
    private static final long CHECK_INTERVAL = 3 * 60 * 1000;

    private final String _xpi2pURLTorrent;
    private boolean _isComplete = false;
    private boolean _hasMetaInfo = false;
    private String _errMsg = "";

    private static final String XPI2P = "app.xpi2p";
    private static final String ZIP = XPI2P + ".zip";
    public static final String PLUGIN_DIR = PluginStarter.PLUGIN_DIR;
    private static final String PROP_ALLOW_NEW_KEYS = "routerconsole.allowUntrustedPlugins";
    private Snark _snark = null;

    public PluginUpdateTorrentRunner(RouterContext ctx, ConsoleUpdateManager mgr, List<URI> uris,
            String appName, String oldVersion) {
        super(ctx, mgr, uris, appName, oldVersion);
        if (uris.size() == 2)
            _xpi2pURLTorrent = uris.get(1).toString();
        else
            _xpi2pURLTorrent = "";
    }

    @Override
    protected void update() {
        _updated = false;
        SnarkManager _smgr = getSnarkManager();
        if (_smgr == null) {
            super.update();
            return;
        }
        if (_xpi2pURLTorrent.endsWith(".torrent")) {
            updateStatus("<b>" + _t("Downloading plugin from {0}", _xpi2pURLTorrent) + "</b>");
            try {
                _get = new EepGet(_context, 1, _updateFile, _xpi2pURLTorrent, false);
                _get.fetch(CONNECT_TIMEOUT, -1, true ? INACTIVITY_TIMEOUT : NOPROXY_INACTIVITY_TIMEOUT);
                File uf = new File(_updateFile);
                if (uf.exists()) {
                    FileInputStream fis = new FileInputStream(uf);
                    MetaInfo torrent = new MetaInfo(fis);
                    fis.close();
                    MagnetURI magnet = new MagnetURI(_smgr.util(), torrent.toMagnetURI());
                    byte[] ih = torrent.getInfoHash();
                    _snark = _smgr.getTorrentByInfoHash(ih);
                    if (_snark != null) {
                        updateStatus(_snark);
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
                    }
                    String name = magnet.getName();
                    String trackerURL = magnet.getTrackerURL();
                    if (trackerURL == null && !_smgr.util().shouldUseDHT() &&
                            !_smgr.util().shouldUseOpenTrackers()) {
                        // but won't we use OT as a failsafe even if disabled?
                        _mgr.notifyAttemptFailed(this, "No tracker, no DHT, no OT", null);
                    }
                    _snark = _smgr.addMagnet(name, ih, trackerURL, true, true, null, this);
                    if (_snark != null) {
                        updateStatus(
                                "<b>" + _smgr.util().getString("Updating from {0}", linkify(torrent.toMagnetURI()))
                                        + "</b>");
                        new Timeout();
                    }
                    _updated = true;
                }
            } catch (Throwable t) {
                _log.error("Error downloading plugin", t);
            }
        } else {
            // attempt an HTTP update using the _xpi2pURL
            super.update();
            return;
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
        SnarkManager _smgr = getSnarkManager();
        if (_smgr == null) {
            _log.error("No SnarkManager, can't find plugin update");
            super.transferComplete(alreadyTransferred, bytesTransferred, bytesRemaining, url, outputFile, notModified);
            return;
        }
        String file = _snark.getBaseName();
        File f = new File(_smgr.getDataDir(), file);
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

    private SnarkManager getSnarkManager() {
        return new SnarkManager(_context);
    }

    public BandwidthListener getBandwidthListener() {
        SnarkManager _smgr = getSnarkManager();
        if (_smgr == null)
            return null;
        return _smgr.getBandwidthListener();
    }

    public boolean shouldAutoStart() {
        SnarkManager _smgr = getSnarkManager();
        if (_smgr == null)
            return false;
        return _smgr.shouldAutoStart();
    }

    public void locked_saveComments(Snark snark, CommentSet comments) {
        SnarkManager _smgr = getSnarkManager();
        if (_smgr == null)
            return;
        _smgr.locked_saveComments(snark, comments);
    }

    @Override
    public void torrentComplete(Snark snark) {
        SnarkManager _smgr = getSnarkManager();
        if (_smgr == null)
            return;
        _smgr.torrentComplete(snark);
    }

    @Override
    public void updateStatus(Snark snark) {
        SnarkManager _smgr = getSnarkManager();
        if (_smgr == null)
            return;
        _smgr.updateStatus(snark);
    }

    @Override
    public String gotMetaInfo(Snark snark) {
        SnarkManager _smgr = getSnarkManager();
        if (_smgr == null)
            return null;
        return _smgr.gotMetaInfo(snark);
    }

    @Override
    public void fatal(Snark snark, String error) {
        SnarkManager _smgr = getSnarkManager();
        if (_smgr == null)
            return;
        _smgr.fatal(snark, error);
    }

    @Override
    public void addMessage(Snark snark, String message) {
        SnarkManager _smgr = getSnarkManager();
        if (_smgr == null)
            return;
        _smgr.addMessage(snark, message);
    }

    @Override
    public void gotPiece(Snark snark) {
        SnarkManager _smgr = getSnarkManager();
        if (_smgr == null)
            return;
        _smgr.gotPiece(snark);
    }

    @Override
    public long getSavedTorrentTime(Snark snark) {
        SnarkManager _smgr = getSnarkManager();
        if (_smgr == null)
            return 0;
        return _smgr.getSavedTorrentTime(snark);
    }

    @Override
    public BitField getSavedTorrentBitField(Snark snark) {
        SnarkManager _smgr = getSnarkManager();
        if (_smgr == null)
            return null;
        return _smgr.getSavedTorrentBitField(snark);
    }

    @Override
    public boolean getSavedPreserveNamesSetting(Snark snark) {
        SnarkManager _smgr = getSnarkManager();
        if (_smgr == null)
            return false;
        return _smgr.getSavedPreserveNamesSetting(snark);
    }

    @Override
    public long getSavedUploaded(Snark snark) {
        SnarkManager _smgr = getSnarkManager();
        if (_smgr == null)
            return 0;
        return _smgr.getSavedUploaded(snark);
    }

    @Override
    public CommentSet getSavedComments(Snark snark) {
        SnarkManager _smgr = getSnarkManager();
        if (_smgr == null)
            return null;
        return _smgr.getSavedComments(snark);
    }

    @Override
    public void start() {
        if (_snark != null)
            _snark.startTorrent();
    }

    private void processComplete(Snark snark) {
        String url = _snark.getMetaInfo().toMagnetURI();
        SnarkManager _smgr = getSnarkManager();
        if (_smgr == null) {
            _log.warn("No SnarkManager");
            return;
        }
        String dataFile = snark.getBaseName();
        File f = new File(_smgr.getDataDir(), dataFile);
        String sudVersion = TrustedUpdate.getVersionString(f);
        if (_newVersion.equals(sudVersion))
            _mgr.notifyComplete(this, _newVersion, f);
        else
            fatal("version mismatch");
        _isComplete = true;
        long alreadyTransferred = f.getAbsoluteFile().length();
        transferComplete(alreadyTransferred, alreadyTransferred, 0, _xpi2pURL, null, false);
    }

    /**
     * This will run twice, once at the metainfo timeout and
     * once at the complete timeout.
     */
    private class Timeout extends SimpleTimer2.TimedEvent {
        private final long _start = _context.clock().now();

        public Timeout() {
            super(_context.simpleTimer2(), METAINFO_TIMEOUT);
        }

        public void timeReached() {
            if (_isComplete || !_isRunning)
                return;
            if (!_hasMetaInfo) {
                fatal("Metainfo timeout");
                return;
            }
            if (_context.clock().now() - _start >= COMPLETE_TIMEOUT) {
                fatal("Complete timeout");
                return;
            }
            reschedule(COMPLETE_TIMEOUT - METAINFO_TIMEOUT);
        }
    }

    /**
     * Rarely used - only if the user added the torrent, so
     * we aren't a complete listener.
     * This will periodically until the complete timeout.
     */
    private class Watcher extends SimpleTimer2.TimedEvent {
        private final long _start = _context.clock().now();

        public Watcher() {
            super(_context.simpleTimer2(), CHECK_INTERVAL);
        }

        public void timeReached() {
            if (_hasMetaInfo && _snark.getRemainingLength() == 0 && !_isComplete)
                processComplete(_snark);
            if (_isComplete || !_isRunning)
                return;
            if (_context.clock().now() - _start >= METAINFO_TIMEOUT && !_hasMetaInfo) {
                fatal("Metainfo timeout");
                return;
            }
            if (_context.clock().now() - _start >= COMPLETE_TIMEOUT) {
                fatal("Complete timeout");
                return;
            }
            notifyProgress();
            reschedule(CHECK_INTERVAL);
        }
    }

    private void fatal(String error) {
        SnarkManager _smgr = getSnarkManager();
        if (_smgr == null) {
            _log.warn("No SnarkManager");
            return;
        }
        if (_snark != null) {
            if (_hasMetaInfo) {
                // avoid loop stopTorrent() ... updateStatus() ... fatal() ...
                if (!_snark.isStopped())
                    _smgr.stopTorrent(_snark, true);
                String file = _snark.getName();
                _smgr.removeTorrent(file);
                // delete torrent file
                File f = new File(_smgr.getDataDir(), file);
                f.delete();
                // delete data
                file = _snark.getBaseName();
                f = new File(_smgr.getDataDir(), file);
                f.delete();
            } else {
                _smgr.deleteMagnet(_snark);
            }
        }
        _mgr.notifyTaskFailed(this, error, null);
        _log.error(error);
        _isRunning = false;
        // stop the tunnel if we were the only one running
        if (_smgr.util().connected() && !_smgr.util().isConnecting()) {
            for (Snark s : _smgr.getTorrents()) {
                if (!s.isStopped())
                    return;
            }
            _smgr.util().disconnect();
        }
    }

    private void notifyProgress() {
        SnarkManager _smgr = getSnarkManager();
        if (_smgr == null) {
            _log.warn("No SnarkManager");
            return;
        }
        if (_hasMetaInfo && _snark != null) {
            long total = _snark.getTotalLength();
            long remaining = _snark.getRemainingLength();
            long transferred = total - remaining;
            String status = "<b>" + _smgr.util().getString("Updating") + "</b>";
            _mgr.notifyProgress(this, status, total - remaining, total);
            bytesTransferred(total, 0, transferred, remaining, _xpi2pURLTorrent);
        }
    }
}
