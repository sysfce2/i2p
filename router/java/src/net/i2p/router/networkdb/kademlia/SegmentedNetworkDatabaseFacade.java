package net.i2p.router.networkdb.kademlia;

import java.io.IOException;
import java.io.Writer;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.HashSet;

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
    public abstract FloodfillNetworkDatabaseFacade clientNetDB(Hash dbid);
    public abstract FloodfillNetworkDatabaseFacade exploratoryNetDB();
    public abstract void shutdown();
    public abstract LeaseSet lookupLeaseSetHashIsClient(Hash key);
    protected abstract LeaseSet lookupLeaseSetLocally(Hash key, String dbid);
    public abstract Set<Hash> getAllRouters(String dbid);
    public abstract Set<Hash> getAllRouters();
    public abstract String getDbidByHash(Hash clientKey);
    public abstract Set<FloodfillNetworkDatabaseFacade> getSubNetDBs();
    public abstract List<String> getClients();
    public int getKnownRouters(String dbid) {
        return getSubNetDB(dbid).getKnownRouters();
    }
    public int getKnownRouters() {
        return mainNetDB().getKnownRouters();
    }
    public int getKnownLeaseSets(String dbid) {
        return getSubNetDB(dbid).getKnownLeaseSets();
    }
    public boolean isInitialized(String dbid) {
        return getSubNetDB(dbid).isInitialized();
    }
    public boolean isInitialized() {
        return mainNetDB().isInitialized();
    }
    public void rescan(String dbid) {
        getSubNetDB(dbid).rescan();
    }
    /** Debug only - all user info moved to NetDbRenderer in router console */
    public void renderStatusHTML(Writer out) throws IOException {
        List<String> clientList = getClients();
        for (String dbid : clientList) {
            getSubNetDB(dbid).renderStatusHTML(out);
        }
    }
    /** public for NetDbRenderer in routerconsole */
    public Set<LeaseSet> getLeases(String dbid) {
        return getSubNetDB(dbid).getLeases();
    }
    /** public for NetDbRenderer in routerconsole */
    public Set<RouterInfo> getRouters(String dbid) {
        return getSubNetDB(dbid).getRouters();
    }
    public Set<RouterInfo> getRouters() {
        return mainNetDB().getRouters();
    }
    public Set<RouterInfo> getRoutersKnownToClients() {
        Set<RouterInfo> ris = new HashSet<>();
        Set<FloodfillNetworkDatabaseFacade> fndfs = getSubNetDBs();
        for (FloodfillNetworkDatabaseFacade fndf : fndfs) {
            ris.addAll(fndf.getRouters());
        }
        return ris;
    }
    public Set<LeaseSet> getLeasesKnownToClients() {
        Set<LeaseSet> lss = new HashSet<>();
        Set<FloodfillNetworkDatabaseFacade> fndfs = getSubNetDBs();
        for (FloodfillNetworkDatabaseFacade fndf : fndfs) {
            lss.addAll(fndf.getLeases());
        }
        return lss;
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
     * For console ConfigKeyringHelper
     * 
     * @return true if removed
     * @since 0.9.59
     */
    public List<String> lookupClientBySigningPublicKey(SigningPublicKey spk) {
        return Collections.emptyList();
    }
    public List<BlindData> getLocalClientsBlindData() {
        return Collections.emptyList();
    }
}
