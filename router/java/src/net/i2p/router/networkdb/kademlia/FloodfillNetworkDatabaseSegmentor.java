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

/**
 * FloodfillNetworkDatabaseSegmentor
 * 
 * Default implementation of the SegmentedNetworkDatabaseFacade.
 * 
 * This is a datastructure which manages (3+Clients) "sub-netDbs" on behalf of an
 * I2P router, each representing it's own view of the network. There are 3 "Special"
 * netDbs:
 * 
 *  - Main NetDB: This is the netDb we use if or when we become a floodfill, and for
 *  direct interaction with other routers on the network, such as when we are communicating
 *  with a floodfill.
 *  - Multihome NetDB: This is used to stash leaseSets for our own sites when they are
 *  sent to us by a floodfill, so that we can reply when they are requested back from us
 *  regardless of our closeness to them in the routing table.
 *  - Exploratory NetDB: This is used when we want to stash a DatabaseEntry for a key
 *  during exploration but don't want it to go into the Main NetDB until we do something
 *  else with it.
 * 
 * And there are an unlimited number of "Client" netDbs. These sub-netDbs are
 * intended to contain only the information required to operate them, and as such
 * most of them are very small, containing only a few LeaseSets belonging to clients.
 * Each one corresponds to a Destination which can recieve information from the
 * netDb, and can be indexed either by it's hash or by it's base32 address. This index
 * is known as the 'dbid' or database id.
 * 
 * Users of this class should strive to always access their sub-netDbs via the
 * explicit DBID of the destination recipient, or using the DBID of the special
 * netDb when it's appropriate to route the netDb entry to one of the special tables.
 * 
 * @author idk
 * @since 0.9.59
 */
public class FloodfillNetworkDatabaseSegmentor extends SegmentedNetworkDatabaseFacade {
    protected final Log _log;
    private RouterContext _context;
    private Map<String, FloodfillNetworkDatabaseFacade> _subDBs = new HashMap<String, FloodfillNetworkDatabaseFacade>();
    public static final String MAIN_DBID = "main";
    private static final String MULTIHOME_DBID = "multihome";
    private static final String EXPLORATORY_DBID = "exploratory";
    private final FloodfillNetworkDatabaseFacade _mainDbid;
    private final FloodfillNetworkDatabaseFacade _multihomeDbid;
    private final FloodfillNetworkDatabaseFacade _exploratoryDbid;

    public FloodfillNetworkDatabaseSegmentor(RouterContext context) {
        super(context);
        _log = context.logManager().getLog(getClass());
        if (_context == null)
            _context = context;
        _mainDbid = new FloodfillNetworkDatabaseFacade(_context, MAIN_DBID);
        _multihomeDbid = new FloodfillNetworkDatabaseFacade(_context, MULTIHOME_DBID);
        _exploratoryDbid = new FloodfillNetworkDatabaseFacade(_context, EXPLORATORY_DBID);
    }

    @Override
    public FloodfillNetworkDatabaseFacade getSubNetDB(Hash id) {
        if (id == null)
            return getSubNetDB(MAIN_DBID);
        return getSubNetDB(id.toBase32());
    }

    @Override
    protected FloodfillNetworkDatabaseFacade getSubNetDB(String id) {
        if (id == null || id.isEmpty() || id.equals(MAIN_DBID))
            return mainNetDB();
        if (id.equals(MULTIHOME_DBID))
            return multiHomeNetDB();
        if (id.equals(EXPLORATORY_DBID))
            return exploratoryNetDB();

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
    protected LeaseSet lookupLeaseSetLocally(Hash key, String dbid) {
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

    public LeaseSet store(Hash key, LeaseSet leaseSet) {
        if (leaseSet == null) {
            return null;
        }
        Hash to = leaseSet.getReceivedBy();
        if (to != null) {
            //String b32 = to.toBase32();
            FloodfillNetworkDatabaseFacade cndb = _context.clientNetDb(to);
            if (_log.shouldLog(Log.DEBUG))
                _log.debug("store " + key.toBase32() + " to client " + to.toBase32());
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
            FloodfillNetworkDatabaseFacade cndb = _context.clientNetDb(to);
            if (_log.shouldLog(Log.DEBUG))
                _log.debug("store " + key.toBase32() + " to client " + to.toBase32());
            if (to != null)
                return cndb.store(key, routerInfo);
        }
        FloodfillNetworkDatabaseFacade fndb = _context.mainNetDb();
        if (_log.shouldLog(Log.DEBUG))
            _log.debug("store " + key.toBase32() + " to main");
        return fndb.store(key, routerInfo);
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
        /*rv.add(MAIN_DBID);
        rv.add(MULTIHOME_DBID);
        rv.add(EXPLORATORY_DBID);*/
        for (String key : _subDBs.keySet()) {
            if (key != null && !key.isEmpty()) {
                if (key.startsWith("client"))
                    rv.add(key);
            }
        }
        return rv;
    }

    @Override
    public FloodfillNetworkDatabaseFacade mainNetDB() {
        return _mainDbid;
    }

    @Override
    public FloodfillNetworkDatabaseFacade multiHomeNetDB() {
        return _multihomeDbid;
    }

    @Override
    public FloodfillNetworkDatabaseFacade clientNetDB(String id) {
        if (id == null || id.isEmpty())
            return exploratoryNetDB();
        return this.getSubNetDB(id);
    }

    @Override
    public FloodfillNetworkDatabaseFacade clientNetDB(Hash id) {
        if (id != null)
            return getSubNetDB(id.toBase32());
        return exploratoryNetDB();
    }

    public FloodfillNetworkDatabaseFacade clientNetDB() {
        return exploratoryNetDB();
    }

    @Override
    public FloodfillNetworkDatabaseFacade exploratoryNetDB() {
        return _exploratoryDbid;
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

    @Override
    public Set<FloodfillNetworkDatabaseFacade> getSubNetDBs() {
        Set<FloodfillNetworkDatabaseFacade> rv = new HashSet<>();
        rv.add(mainNetDB());
        rv.add(multiHomeNetDB());
        rv.add(exploratoryNetDB());
        rv.addAll(_subDBs.values());
        return rv;
    }

    @Override
    public List<BlindData> getLocalClientsBlindData() {
        List<BlindData> rv = new ArrayList<>();
        for (FloodfillNetworkDatabaseFacade subdb : _subDBs.values()) {
            rv.addAll(subdb.getBlindData());
        }
        return rv;
    }
}
