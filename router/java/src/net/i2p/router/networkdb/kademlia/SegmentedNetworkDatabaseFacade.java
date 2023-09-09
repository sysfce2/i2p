package net.i2p.router.networkdb.kademlia;

import java.io.IOException;
import java.io.Writer;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import net.i2p.data.BlindData;
import net.i2p.data.DatabaseEntry;
import net.i2p.data.Destination;
import net.i2p.data.Hash;
import net.i2p.data.LeaseSet;
import net.i2p.data.SigningPublicKey;
import net.i2p.data.router.RouterInfo;
import net.i2p.router.Job;
import net.i2p.router.NetworkDatabaseFacade;
import net.i2p.router.RouterContext;
import net.i2p.router.networkdb.reseed.ReseedChecker;

public abstract class SegmentedNetworkDatabaseFacade { // extends FloodfillNetworkDatabaseFacade {
    public SegmentedNetworkDatabaseFacade(RouterContext context) {
        // super(context, null);
    }

    protected abstract FloodfillNetworkDatabaseFacade getSubNetDB(String dbid);
    public abstract FloodfillNetworkDatabaseFacade getSubNetDB(Hash dbid);

    public abstract FloodfillNetworkDatabaseFacade mainNetDB();

    public abstract FloodfillNetworkDatabaseFacade multiHomeNetDB();

    public abstract FloodfillNetworkDatabaseFacade clientNetDB(String dbid);

    public abstract FloodfillNetworkDatabaseFacade exploratoryNetDB();

    public abstract FloodfillNetworkDatabaseFacade localNetDB();

    public abstract void shutdown();

    public abstract LeaseSet lookupLeaseSetHashIsClient(Hash key);

    protected abstract LeaseSet lookupLeaseSetLocally(Hash key, String dbid);

    public abstract Set<Hash> getAllRouters(String dbid);
    public abstract Set<Hash> getAllRouters();

    public int getKnownRouters(String dbid) {
        return 0;
    }

    public int getKnownRouters() {
        return 0;
    }

    public int getKnownLeaseSets(String dbid) {
        return 0;
    }

    public boolean isInitialized(String dbid) {
        return true;
    }

    public boolean isInitialized() {
        return true;
    }

    public void rescan(String dbid) {
    }

    /** Debug only - all user info moved to NetDbRenderer in router console */
    public void renderStatusHTML(Writer out) throws IOException {
    }

    /** public for NetDbRenderer in routerconsole */
    public Set<LeaseSet> getLeases(String dbid) {
        return Collections.emptySet();
    }

    /** public for NetDbRenderer in routerconsole */
    public Set<RouterInfo> getRouters(String dbid) {
        return Collections.emptySet();
    }

    public Set<RouterInfo> getRouters() {
        return Collections.emptySet();
    }

    public Set<RouterInfo> getRoutersKnownToClients() {
        return Collections.emptySet();
    }

    public Set<LeaseSet> getLeasesKnownToClients() {
        return Collections.emptySet();
    }

    public List<String> getClients() {
        return Collections.emptyList();
    }

    /** @since 0.9.59 */
    public ReseedChecker reseedChecker() {
        return mainNetDB().reseedChecker();
    };

    /**
     * For convenience, so users don't have to cast to FNDF, and unit tests using
     * Dummy NDF will work.
     *
     * @return false; FNDF overrides to return actual setting
     * @since IPv6
     */
    public boolean floodfillEnabled() {
        return mainNetDB().floodfillEnabled();
    };

    /**
     * @param spk unblinded key
     * @return BlindData or null
     * @since 0.9.59
     */
    public BlindData getBlindData(SigningPublicKey spk) {
        return mainNetDB().getBlindData(spk);
    }

    public List<BlindData> getLocalClientsBlindData() {
        return mainNetDB().getBlindData();
    }

    /**
     * For console ConfigKeyringHelper
     * 
     * @return true if removed
     * @since 0.9.59
     */
    public List<String> lookupClientBySigningPublicKey(SigningPublicKey spk) {
        return Collections.emptyList();
    }

    public abstract String getDbidByHash(Hash clientKey);
}
