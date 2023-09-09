package net.i2p.router.networkdb.kademlia;

import java.io.IOException;
import java.io.Writer;
//import java.rmi.dgc.Lease;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.i2p.data.BlindData;
import net.i2p.data.DatabaseEntry;
import net.i2p.data.Destination;
import net.i2p.data.Hash;
import net.i2p.data.LeaseSet;
import net.i2p.data.SigningPublicKey;
import net.i2p.data.TunnelId;
import net.i2p.data.router.RouterInfo;
import net.i2p.router.Job;
import net.i2p.router.RouterContext;
import net.i2p.router.networkdb.reseed.ReseedChecker;
import net.i2p.util.Log;

public class FloodfillNetworkDatabaseSegmentor extends SegmentedNetworkDatabaseFacade {
    protected final Log _log;
    private RouterContext _context;
    private Map<String, FloodfillNetworkDatabaseFacade> _subDBs = new HashMap<String, FloodfillNetworkDatabaseFacade>();
    public static final String MAIN_DBID = "main";
    private static final String MULTIHOME_DBID = "multihome";

    public FloodfillNetworkDatabaseSegmentor(RouterContext context) {
        super(context);
        _log = context.logManager().getLog(getClass());
        if (_context == null)
            _context = context;
        FloodfillNetworkDatabaseFacade subdb = new FloodfillNetworkDatabaseFacade(_context, MAIN_DBID);
        _subDBs.put(MAIN_DBID, subdb);
    }

    /*
     * public FloodfillNetworkDatabaseFacade getSubNetDB() {
     * return this;
     * }
     */
    @Override
    public FloodfillNetworkDatabaseFacade getSubNetDB(Hash id) {
        if (id == null)
            return getSubNetDB(MAIN_DBID);
        return getSubNetDB(id.toBase32());
    }

    @Override
    protected FloodfillNetworkDatabaseFacade getSubNetDB(String id) {
        if (id == null || id.isEmpty()) {
            return getSubNetDB(MAIN_DBID);
        }
        if (id.endsWith(".i2p")) {
            if (!id.startsWith("clients_"))
                id = "clients_" + id;
        }
        FloodfillNetworkDatabaseFacade subdb = _subDBs.get(id);
        if (subdb == null) {
            subdb = new FloodfillNetworkDatabaseFacade(_context, id);
            _subDBs.put(id, subdb);
            subdb.startup();
            subdb.createHandlers();
            if (subdb.getFloodfillPeers().size() == 0) {
                List<RouterInfo> ris = mainNetDB().pickRandomFloodfillPeers();
                for (RouterInfo ri : ris) {
                    if (_log.shouldLog(_log.DEBUG))
                        _log.debug("Seeding: " + id + " with " + ris.size() + " peers " + ri.getHash());
                    subdb.store(ri.getIdentity().getHash(), ri);
                }
            }
        }
        return subdb;
    }

    /**
     * If we are floodfill, turn it off and tell everybody.
     * 
     * @since 0.8.9
     */
    public synchronized void shutdown() {
        // shut down every entry in _subDBs
        for (FloodfillNetworkDatabaseFacade subdb : _subDBs.values()) {
            if (_log.shouldLog(Log.DEBUG))
                _log.debug("(dbid: " + subdb._dbid
                        + ") Shutting down all remaining sub-netDbs",
                        new Exception());
            subdb.shutdown();
        }
    }

    /**
     * This maybe could be shorter than
     * RepublishLeaseSetJob.REPUBLISH_LEASESET_TIMEOUT,
     * because we are sending direct, but unresponsive floodfills may take a while
     * due to timeouts.
     */
    static final long PUBLISH_TIMEOUT = 90 * 1000;

    /**
     * @param type      database store type
     * @param lsSigType may be null
     * @since 0.9.39
     */
    /*
     * private boolean shouldFloodTo(Hash key, int type, SigType lsSigType, Hash
     * peer, RouterInfo target) {
     * return subdb.shouldFloodTo(key, type, lsSigType, peer,
     * target);
     * }
     */

    protected PeerSelector createPeerSelector(String dbid) {
        return this.getSubNetDB(dbid).createPeerSelector();
    }

    public List<RouterInfo> getKnownRouterData() {
        List<RouterInfo> rv = new ArrayList<RouterInfo>();
        for (FloodfillNetworkDatabaseFacade subdb : _subDBs.values()) {
            if (_log.shouldLog(Log.DEBUG))
                _log.debug("(dbid: " + subdb._dbid
                        + ") Deprecated! Arbitrary selection of this subDb",
                        new Exception());
            rv.addAll(subdb.getKnownRouterData());
        }
        return rv;
    }

    /**
     * list of the Hashes of currently known floodfill peers;
     * Returned list will not include our own hash.
     * List is not sorted and not shuffled.
     */
    public List<Hash> getFloodfillPeers() {
        List<Hash> peers = new ArrayList<Hash>();
        for (FloodfillNetworkDatabaseFacade subdb : _subDBs.values()) {
            if (_log.shouldLog(Log.DEBUG))
                _log.debug("(dbid: " + subdb._dbid
                        + ") Deprecated! Arbitrary selection of this subDb",
                        new Exception());
            peers.addAll(subdb.getFloodfillPeers());
        }
        return peers;
    }

    /**
     * Return the RouterInfo structures for the routers closest to the given key.
     * At most maxNumRouters will be returned
     *
     * @param key           The key
     * @param maxNumRouters The maximum number of routers to return
     * @param peersToIgnore Hash of routers not to include
     */
    @Override
    public Set<Hash> findNearestRouters(Hash key, int maxNumRouters, Set<Hash> peersToIgnore, String dbid) {
        return getSubNetDB(dbid).findNearestRouters(key, maxNumRouters, peersToIgnore);
    }

    /**
     * @return RouterInfo, LeaseSet, or null
     * @since 0.8.3
     */
    @Override
    public DatabaseEntry lookupLocally(Hash key, String dbid) {
        if (dbid == null || dbid.isEmpty()) {
            return null;
            /*DatabaseEntry rv = null;
            for (FloodfillNetworkDatabaseFacade subdb : _subDBs.values()) {
                if (_log.shouldLog(Log.DEBUG))
                    _log.debug("(dbid: " + subdb._dbid
                            + ") Deprecated! Arbitrary selection of this subDb",
                            new Exception());
                rv = subdb.lookupLocally(key);
                if (rv != null) {
                    return rv;
                }
            }
            rv = this.lookupLocally(key, MAIN_DBID);
            if (rv != null) {
                return rv;
            }*/
        }
        return this.getSubNetDB(dbid).lookupLocally(key);
    }

    /**
     * Not for use without validation
     * 
     * @return RouterInfo, LeaseSet, or null, NOT validated
     * @since 0.9.38
     */
    @Override
    public DatabaseEntry lookupLocallyWithoutValidation(Hash key, String dbid) {
        if (dbid == null || dbid.isEmpty()) {
            DatabaseEntry rv = null;
            for (FloodfillNetworkDatabaseFacade subdb : _subDBs.values()) {
                if (_log.shouldLog(Log.DEBUG))
                    _log.debug("(dbid: " + subdb._dbid
                            + ") Deprecated! Arbitrary selection of this subDb",
                            new Exception());
                rv = subdb.lookupLocallyWithoutValidation(key);
                if (rv != null) {
                    return rv;
                }
            }
            rv = this.lookupLocallyWithoutValidation(key, MAIN_DBID);
            if (rv != null) {
                return rv;
            }
        }
        return this.getSubNetDB(dbid).lookupLocallyWithoutValidation(key);
    }

    @Override
    public void lookupLeaseSet(Hash key, Job onFindJob, Job onFailedLookupJob, long timeoutMs, String dbid) {
        this.getSubNetDB(dbid).lookupLeaseSet(key, onFindJob, onFailedLookupJob, timeoutMs);
    }

    /**
     * Lookup using the client's tunnels
     * 
     * @param fromLocalDest use these tunnels for the lookup, or null for
     *                      exploratory
     * @since 0.9.10
     */
    @Override
    public void lookupLeaseSet(Hash key, Job onFindJob, Job onFailedLookupJob, long timeoutMs, Hash fromLocalDest,
            String dbid) {
        if (dbid == null || dbid.isEmpty()) {
            dbid = fromLocalDest.toBase32();
        }
        this.getSubNetDB(dbid).lookupLeaseSet(key, onFindJob, onFailedLookupJob, timeoutMs, fromLocalDest);
    }

    /**
     * Lookup using the client's tunnels when the client LS key is know
     * but the client dbid is not.
     *
     * @param key The LS key for client.
     * @since 0.9.60
     */
    @Override
    public LeaseSet lookupLeaseSetHashIsClient(Hash key) {
        String dbid = matchDbid(key);
        return lookupLeaseSetLocally(key, dbid);
    }

    @Override
    public LeaseSet lookupLeaseSetLocally(Hash key, String dbid) {
        if (dbid == null || dbid.isEmpty()) {
            LeaseSet rv = null;
            for (FloodfillNetworkDatabaseFacade subdb : _subDBs.values()) {
                if (_log.shouldLog(Log.DEBUG))
                    _log.debug("(dbid: " + subdb._dbid
                            + ") Deprecated! Arbitrary selection of this subDb",
                            new Exception());
                rv = subdb.lookupLeaseSetLocally(key);
                if (rv != null) {
                    return rv;
                }
            }
            rv = this.lookupLeaseSetLocally(key, MAIN_DBID);
            if (rv != null) {
                return rv;
            }
        }
        return this.getSubNetDB(dbid).lookupLeaseSetLocally(key);
    }

    @Override
    public void lookupRouterInfo(Hash key, Job onFindJob, Job onFailedLookupJob, long timeoutMs, String dbid) {
        this.getSubNetDB(dbid).lookupRouterInfo(key, onFindJob, onFailedLookupJob, timeoutMs);
    }

    @Override
    public RouterInfo lookupRouterInfoLocally(Hash key, String dbid) {
        if (dbid == null || dbid.isEmpty()) {
            RouterInfo ri = mainNetDB().lookupRouterInfoLocally(key);
            if (ri != null) {
                return ri;
            }
            for (FloodfillNetworkDatabaseFacade subdb : _subDBs.values()) {
                if (_log.shouldLog(Log.DEBUG))
                    _log.debug("(dbid: " + subdb._dbid
                            + ") Deprecated! Arbitrary selection of this subDb",
                            new Exception());
                ri = subdb.lookupRouterInfoLocally(key);
                if (ri != null) {
                    return ri;
                }
            }
        }
        return this.getSubNetDB(dbid).lookupRouterInfoLocally(key);
    }

    /**
     * Unconditionally lookup using the client's tunnels.
     * No success or failed jobs, no local lookup, no checks.
     * Use this to refresh a leaseset before expiration.
     *
     * @param fromLocalDest use these tunnels for the lookup, or null for
     *                      exploratory
     * @since 0.9.25
     */
    @Override
    public void lookupLeaseSetRemotely(Hash key, Hash fromLocalDest, String dbid) {
        this.getSubNetDB(dbid).lookupLeaseSetRemotely(key, fromLocalDest);
    }

    /**
     * Unconditionally lookup using the client's tunnels.
     *
     * @param fromLocalDest     use these tunnels for the lookup, or null for
     *                          exploratory
     * @param onFindJob         may be null
     * @param onFailedLookupJob may be null
     * @since 0.9.47
     */
    @Override
    public void lookupLeaseSetRemotely(Hash key, Job onFindJob, Job onFailedLookupJob,
            long timeoutMs, Hash fromLocalDest, String dbid) {
        this.getSubNetDB(dbid).lookupLeaseSetRemotely(key, onFindJob, onFailedLookupJob, timeoutMs, fromLocalDest);
    }

    /**
     * Lookup using the client's tunnels
     * Succeeds even if LS validation fails due to unsupported sig type
     *
     * @param fromLocalDest use these tunnels for the lookup, or null for
     *                      exploratory
     * @since 0.9.16
     */
    @Override
    public void lookupDestination(Hash key, Job onFinishedJob, long timeoutMs, Hash fromLocalDest, String dbid) {
        if (dbid == null || dbid.isEmpty()) {
            if (fromLocalDest != null)
                dbid = fromLocalDest.toBase32();
            else
                dbid = null;
        }
        this.getSubNetDB(dbid).lookupDestination(key, onFinishedJob, timeoutMs, fromLocalDest);
    }

    /**
     * Lookup locally in netDB and in badDest cache
     * Succeeds even if LS validation failed due to unsupported sig type
     *
     * @since 0.9.16
     */
    @Override
    public Destination lookupDestinationLocally(Hash key, String dbid) {
        return this.getSubNetDB(dbid).lookupDestinationLocally(key);
    }

    /**
     * @return the leaseSet if another leaseSet already existed at that key
     *
     * @throws IllegalArgumentException if the data is not valid
     */
    @Override
    public LeaseSet store(Hash key, LeaseSet leaseSet, String dbid) throws IllegalArgumentException {
        if (dbid == null || dbid.isEmpty()) {
            if (key != null)
                dbid = key.toBase32();
        }
        return getSubNetDB(dbid).store(key, leaseSet);
    }

    public LeaseSet store(Hash key, LeaseSet leaseSet) {
        if (leaseSet == null) {
            return null;
        }
        Hash to = leaseSet.getReceivedBy();
        if (to != null) {
            String b32 = to.toBase32();
            FloodfillNetworkDatabaseFacade cndb = _context.clientNetDb(b32);
            if (_log.shouldLog(Log.DEBUG))
                _log.debug("store " + key.toBase32() + " to client " + b32);
            if (b32 != null)
                return cndb.store(key, leaseSet);
        }
        FloodfillNetworkDatabaseFacade fndb = _context.mainNetDb();
        if (_log.shouldLog(Log.DEBUG))
            _log.debug("store " + key.toBase32() + " to main");
        return fndb.store(key, leaseSet);
    }

    public RouterInfo store(Hash key, RouterInfo routerInfo) {
        Hash to = routerInfo.getReceivedBy();
        if (to != null) {
            String b32 = to.toBase32();
            FloodfillNetworkDatabaseFacade cndb = _context.clientNetDb(b32);
            if (_log.shouldLog(Log.DEBUG))
                _log.debug("store " + key.toBase32() + " to client " + b32);
            if (b32 != null)
                return cndb.store(key, routerInfo);
        }
        FloodfillNetworkDatabaseFacade fndb = _context.mainNetDb();
        if (_log.shouldLog(Log.DEBUG))
            _log.debug("store " + key.toBase32() + " to main");
        return fndb.store(key, routerInfo);
    }

    /**
     * @return the routerInfo if another router already existed at that key
     *
     * @throws IllegalArgumentException if the data is not valid
     */
    @Override
    public RouterInfo store(Hash key, RouterInfo routerInfo, String dbid) throws IllegalArgumentException {
        return getSubNetDB(dbid).store(key, routerInfo);
    }

    /**
     * @return the old entry if it already existed at that key
     * @throws IllegalArgumentException if the data is not valid
     * @since 0.9.16
     */
    @Override
    public DatabaseEntry store(Hash key, DatabaseEntry entry, String dbid) throws IllegalArgumentException {
        if (entry.getType() == DatabaseEntry.KEY_TYPE_ROUTERINFO)
            return store(key, (RouterInfo) entry, dbid);
        if (entry.getType() == DatabaseEntry.KEY_TYPE_LEASESET)
            return store(key, (LeaseSet) entry, dbid);
        throw new IllegalArgumentException("unknown type");
    }

    @Override
    public Set<Hash> getAllRouters(String dbid) {
        if (dbid == null || dbid.isEmpty()) {
            return getAllRouters();
        }
        return this.getSubNetDB(dbid).getAllRouters();
    }

    public Set<Hash> getAllRouters() {
        Set<Hash> routers = new HashSet<Hash>();
        for (FloodfillNetworkDatabaseFacade subdb : _subDBs.values()) {
            if (_log.shouldLog(Log.DEBUG))
                _log.debug("(dbid: " + subdb._dbid
                        + ") Deprecated! Arbitrary selection of this subDb",
                        new Exception());
            routers.addAll(subdb.getAllRouters());
        }
        return routers;
    }

    @Override
    public int getKnownRouters(String dbid) {
        return this.getSubNetDB(dbid).getKnownRouters();
    }

    public int getKnownRouters() {
        int total = 0;
        for (FloodfillNetworkDatabaseFacade subdb : _subDBs.values()) {
            if (_log.shouldLog(Log.DEBUG))
                _log.debug("(dbid: " + subdb._dbid
                        + ") Deprecated! Arbitrary selection of this subDb",
                        new Exception());
            total += subdb.getKnownRouters();
        }
        return total;
    }

    @Override
    public int getKnownLeaseSets(String dbid) {
        return this.getSubNetDB(dbid).getKnownLeaseSets();
    }

    @Override
    public boolean isInitialized(String dbid) {
        return this.getSubNetDB(dbid).isInitialized();
    }

    public boolean isInitialized() {
        boolean rv = false;
        for (FloodfillNetworkDatabaseFacade subdb : _subDBs.values()) {
            rv = subdb.isInitialized();
            if (!rv) {
                break;
            }
        }
        return rv;
    }

    @Override
    public void rescan(String dbid) {
        this.getSubNetDB(dbid).rescan();
    }

    /** Debug only - all user info moved to NetDbRenderer in router console */
    @Override
    public void renderStatusHTML(Writer out) throws IOException {
        for (FloodfillNetworkDatabaseFacade subdb : _subDBs.values()) {
            subdb.renderStatusHTML(out);
        }
    }

    /** public for NetDbRenderer in routerconsole */
    @Override
    public Set<LeaseSet> getLeases(String dbid) {
        return this.getSubNetDB(dbid).getLeases();
    }

    /** public for NetDbRenderer in routerconsole */
    @Override
    public Set<RouterInfo> getRouters(String dbid) {
        if (dbid == null || dbid.isEmpty()) {
            Set<RouterInfo> rv = new HashSet<>();
            for (FloodfillNetworkDatabaseFacade subdb : _subDBs.values()) {
                if (_log.shouldLog(Log.DEBUG))
                    _log.debug("(dbid: " + subdb._dbid
                            + ") Deprecated! Collecting RouterInfos from SubDbs",
                            new Exception());
                rv.addAll(subdb.getRouters());
            }
            return rv;
        }
        return this.getSubNetDB(dbid).getRouters();
    }

    @Override
    public Set<RouterInfo> getRouters() {
        Set<RouterInfo> rv = new HashSet<>();
        for (FloodfillNetworkDatabaseFacade subdb : _subDBs.values()) {
            if (_log.shouldLog(Log.DEBUG))
                _log.debug("(dbid: " + subdb._dbid
                        + ") Deprecated! Arbitrary selection of this subDb",
                        new Exception());
            rv.addAll(subdb.getRouters());
        }
        return rv;
    }

    public Set<RouterInfo> getRoutersKnownToClients() {
        Set<RouterInfo> rv = new HashSet<>();
        for (String key : _subDBs.keySet()) {
            if (key != null && !key.isEmpty()) {
                if (key.startsWith("client"))
                    rv.addAll(this.getSubNetDB(key).getRouters());
            }
        }
        return rv;
    }

    public Set<LeaseSet> getLeasesKnownToClients() {
        Set<LeaseSet> rv = new HashSet<>();
        for (String key : _subDBs.keySet()) {
            if (key != null && !key.isEmpty()) {
                if (key.startsWith("client"))
                    rv.addAll(this.getSubNetDB(key).getLeases());
            }
        }
        return rv;
    }

    public List<String> getClients() {
        List<String> rv = new ArrayList<String>();
        for (String key : _subDBs.keySet()) {
            if (key != null && !key.isEmpty()) {
                if (key.startsWith("client"))
                    rv.add(key);
            }
        }
        return rv;
    }

    /**
     * Is it permanently negative cached?
     *
     * @param key only for Destinations; for RouterIdentities, see Banlist
     * @since 0.9.16
     */
    @Override
    public boolean isNegativeCachedForever(Hash key, String dbid) {
        return this.getSubNetDB(dbid).isNegativeCached(key);
    }

    /**
     * @param spk unblinded key
     * @return BlindData or null
     * @since 0.9.40
     */
    public BlindData getBlindData(SigningPublicKey spk, String dbid) {
        return this.getSubNetDB(dbid).getBlindData(spk);
    }

    /**
     * @param bd new BlindData to put in the cache
     * @since 0.9.40
     */
    @Override
    public void setBlindData(BlindData bd, String dbid) {
        this.getSubNetDB(dbid).setBlindData(bd);
    }

    /**
     * For console ConfigKeyringHelper
     * 
     * @since 0.9.41
     */
    @Override
    public List<BlindData> getBlindData(String dbid) {
        return this.getSubNetDB(dbid).getBlindData();
    }

    /**
     * For console ConfigKeyringHelper
     * 
     * @return true if removed
     * @since 0.9.41
     */
    @Override
    public boolean removeBlindData(SigningPublicKey spk, String dbid) {
        return this.getSubNetDB(dbid).removeBlindData(spk);
    }

    @Override
    public FloodfillNetworkDatabaseFacade mainNetDB() {
        return this.getSubNetDB(MAIN_DBID);
    }

    @Override
    public FloodfillNetworkDatabaseFacade multiHomeNetDB() {
        return this.getSubNetDB(MULTIHOME_DBID);
    }

    @Override
    public FloodfillNetworkDatabaseFacade clientNetDB(String id) {
        if (id == null || id.isEmpty())
            return exploratoryNetDB();
        return this.getSubNetDB(id);
    }

    public FloodfillNetworkDatabaseFacade clientNetDB() {
        return clientNetDB(null);
    }

    @Override
    public FloodfillNetworkDatabaseFacade exploratoryNetDB() {
        return this.getSubNetDB("exploratory");
    }

    @Override
    public FloodfillNetworkDatabaseFacade localNetDB() {
        return this.getSubNetDB("local");
    }

    @Override
    public List<BlindData> getLocalClientsBlindData() {
        ArrayList<BlindData> rv = new ArrayList<>();
        for (String subdb : _subDBs.keySet()) {
            // if (subdb.startsWith("clients_"))
            // TODO: see if we can access only one subDb at a time when we need
            // to look up a client by SPK. We mostly need this for managing blinded
            // and encrypted keys in the Keyring Config UI page. See also
            // ConfigKeyringHelper
            rv.addAll(_subDBs.get(subdb).getBlindData());
        }
        return rv;
    }

    @Override
    public List<String> lookupClientBySigningPublicKey(SigningPublicKey spk) {
        List<String> rv = new ArrayList<>();
        for (String subdb : _subDBs.keySet()) {
            // if (subdb.startsWith("clients_"))
            // TODO: see if we can access only one subDb at a time when we need
            // to look up a client by SPK. We mostly need this for managing blinded
            // and encrypted keys in the Keyring Config UI page. See also
            // ConfigKeyringHelper
            BlindData bd = _subDBs.get(subdb).getBlindData(spk);
            if (bd != null) {
                rv.add(subdb);
            }
        }
        return rv;
    }

    /**
     * Public helper to return the dbid that is associated with the
     * supplied client key.
     *
     * @param clientKey The LS key of the subDb context
     * @since 0.9.60
     */
    @Override
    public String getDbidByHash(Hash clientKey) {
        return matchDbid(clientKey);
    }

    /**
     * Return the dbid that is associated with the supplied client LS key
     *
     * @param clientKey The LS key of the subDb context
     * @since 0.9.60
     */
    private String matchDbid(Hash clientKey) {
        for (FloodfillNetworkDatabaseFacade subdb : _subDBs.values()) {
            if (subdb.matchClientKey(clientKey))
                return subdb._dbid;
        }
        return null;
    }
}
