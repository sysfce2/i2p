package net.i2p.router.networkdb.kademlia;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import net.i2p.data.BlindData;
import net.i2p.data.Hash;
import net.i2p.data.LeaseSet;
import net.i2p.data.SigningPublicKey;
import net.i2p.data.router.RouterInfo;
import net.i2p.router.RouterContext;
import net.i2p.util.Log;

/**
 * FloodfillNetworkDatabaseSegmentor
 * 
 * Default implementation of the SegmentedNetworkDatabaseFacade.
 * 
 * This is a datastructure which manages (3+Clients) "sub-netDbs" on behalf of an
 * I2P router, each representing it's own view of the network. Normally, these sub-netDb's
 * are identified by the hash of the primary session belonging to the client who "owns"
 * a particular sub-netDb.
 * 
 * There are 3 "Special" netDbs which have non-hash names:
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
 * @since 0.9.60
 */
public class FloodfillNetworkDatabaseSegmentor extends SegmentedNetworkDatabaseFacade {
    protected final Log _log;
    private RouterContext _context;
    private static final String PROP_NETDB_ISOLATION = "router.netdb.isolation";
    public static final Hash MAIN_DBID = null;
    public static final Hash MULTIHOME_DBID = null;
    public static final Hash EXPLORATORY_DBID = Hash.FAKE_HASH;
    private final FloodfillNetworkDatabaseFacade _mainDbid;
    private final FloodfillNetworkDatabaseFacade _multihomeDbid;
    private final FloodfillNetworkDatabaseFacade _exploratoryDbid;

    /**
     * Construct a new FloodfillNetworkDatabaseSegmentor with the given
     * RouterContext, containing a default, main netDb and a multihome netDb
     * and which is prepared to add client netDbs.
     * 
     * @since 0.9.60
     */
    public FloodfillNetworkDatabaseSegmentor(RouterContext context) {
        super(context);
        _log = context.logManager().getLog(getClass());
        if (_context == null)
            _context = context;
        _mainDbid = new FloodfillNetworkDatabaseFacade(_context, MAIN_DBID);
        _multihomeDbid = new FloodfillNetworkDatabaseFacade(_context, MULTIHOME_DBID);
        _exploratoryDbid = new FloodfillNetworkDatabaseFacade(_context, EXPLORATORY_DBID);
    }

    private boolean useSubDbs() {
        return _context.getProperty(PROP_NETDB_ISOLATION, true);
    }

    /**
     * Retrieves the FloodfillNetworkDatabaseFacade object for the specified ID.
     * If the ID is null, the main database is returned.
     *
     * @param  id  the ID of the FloodfillNetworkDatabaseFacade object to retrieve
     * @return     the FloodfillNetworkDatabaseFacade object corresponding to the ID
     */
    @Override
    protected FloodfillNetworkDatabaseFacade getSubNetDB(Hash id) {
        if (!useSubDbs())
            return mainNetDB();
        if (id == null)
            return mainNetDB();
        return _context.clientManager().getClientFloodfillNetworkDatabaseFacade(id);
    }

    /**
     * If we are floodfill, turn it off and tell everybody.
     * Shut down all known subDbs.
     * 
     * @since 0.9.60
     * 
     */
    public synchronized void shutdown() {
        if (_log.shouldLog(Log.DEBUG))
                _log.debug("shutdown called from FNDS, shutting down all remaining sub-netDbs");
        _mainDbid.shutdown();
        _multihomeDbid.shutdown();
        // shut down every entry in _subDBs
        for (FloodfillNetworkDatabaseFacade subdb : getClientSubNetDBs()) {
            if (_log.shouldLog(Log.DEBUG))
                _log.debug("(dbid: " + subdb._dbid
                        + ") Shutting down all remaining subDbs");
            subdb.shutdown();
        }
    }

    /**
     * list of the RouterInfo objects for all known peers;
     * 
     * @since 0.9.60
     * 
     */
    public List<RouterInfo> getKnownRouterData() {
        List<RouterInfo> rv = new ArrayList<RouterInfo>();
        for (FloodfillNetworkDatabaseFacade subdb : getSubNetDBs()) {
            if (_log.shouldLog(Log.DEBUG))
                _log.debug("getKnownRouterData Called from FNDS,"+subdb._dbid+", will be combined with all other subDbs");
            rv.addAll(subdb.getKnownRouterData());
        }
        return rv;
    }

    /**
     * list of the Hashes of currently known floodfill peers;
     * Returned list will not include our own hash.
     * List is not sorted and not shuffled.
     * 
     * @since 0.9.60
     */
    public List<Hash> getFloodfillPeers() {
        if (_log.shouldLog(Log.DEBUG))
            _log.debug("getFloodfillPeers collecting all floodfill peers across all subDbs");
        List<Hash> peers = new ArrayList<Hash>();
        for (FloodfillNetworkDatabaseFacade subdb : getSubNetDBs()) {
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
        Hash dbid = matchDbid(key);
        return lookupLeaseSetLocally(key, dbid);
    }

    /**
     * Lookup using the client's tunnels when the client LS key is known.
     * if a DBID is not provided, the clients will all be checked, and the
     * first value will be used.
     * 
     * @since 0.9.60
     * 
     */
    //@Override
    protected LeaseSet lookupLeaseSetLocally(Hash key, Hash dbid) {
        if (_log.shouldLog(Log.DEBUG))
            _log.debug("lookupLeaseSetLocally on all subDbs: " + key.toBase32());
        if (dbid == null) {
            LeaseSet rv = null;
            for (FloodfillNetworkDatabaseFacade subdb : getClientSubNetDBs()) {
                rv = subdb.lookupLeaseSetLocally(key);
                if (rv != null) {
                    return rv;
                }
            }
        }
        return this.getSubNetDB(dbid).lookupLeaseSetLocally(key);
    }

    /**
     * Check if all of the known subDbs are initialized
     * 
     * @since 0.9.60
     * 
     */
    public boolean isInitialized() {
        if (_mainDbid == null)
            return false;
        boolean rv = mainNetDB().isInitialized();
        if (!rv)
            return rv;
        for (FloodfillNetworkDatabaseFacade subdb : getClientSubNetDBs()) {
            rv = subdb.isInitialized();
            if (!rv) {
                break;
            }
        }
        return rv;
    }

    /**
     * list of the RouterInfo objects for all known peers
     * 
     * @since 0.9.60
     * 
     */
    @Override
    public Set<RouterInfo> getRouters() {
        if (_log.shouldLog(Log.DEBUG))
            _log.debug("getRouters called from FNDS, collecting routers from all subDbs");
        Set<RouterInfo> rv = new HashSet<>();
        for (FloodfillNetworkDatabaseFacade subdb : getSubNetDBs()) {
            rv.addAll(subdb.getRouters());
        }
        return rv;
    }



    /**
     * list of the RouterInfo objects for all known peers known to clients(in subDbs) only
     * 
     * @since 0.9.60
     * 
     */
    public Set<RouterInfo> getRoutersKnownToClients() {
        Set<RouterInfo> rv = new HashSet<>();
        for (Hash key : getClients()) {
            FloodfillNetworkDatabaseFacade sndb = this.getSubNetDB(key);
            if (sndb != null) {
                Set<RouterInfo> rv2 = sndb.getRouters();
                if (rv2 != null)
                    rv.addAll(rv2);
            }
        }
        return rv;
    }

    /**
     * list of the LeaseSet objects for all known peers known to clients(in subDbs) only
     * 
     * @since 0.9.60
     * 
     */
    public Set<LeaseSet> getLeasesKnownToClients() {
        Set<LeaseSet> rv = new HashSet<>();
        for (Hash key : getClients()) {
            FloodfillNetworkDatabaseFacade sndb = this.getSubNetDB(key);
            if (sndb != null) {
                Set<LeaseSet> rv2 = sndb.getLeases();
                if (rv2 != null)
                    rv.addAll(rv2);
            }
        }
        return rv;
    }

    /**
     * list all of the dbids of all known client subDbs
     * 
     * @since 0.9.60
     * 
     */
    public List<Hash> getClients() {
        List<Hash> rv = new ArrayList<Hash>();
        Set<FloodfillNetworkDatabaseFacade> subNetDBs = getClientSubNetDBs();
        for (FloodfillNetworkDatabaseFacade subdb : subNetDBs) {
            rv.add(subdb._dbid);
        }
        return rv;
    }

    /**
     * get the main netDb, which is the one we will use if we are a floodfill
     * 
     * @since 0.9.60
     * 
     */
    @Override
    public FloodfillNetworkDatabaseFacade mainNetDB() {
        return _mainDbid;
    }

    /**
     * get the multiHome netDb, which is especially for handling multihomes
     * 
     * @since 0.9.60
     * 
     */
    @Override
    public FloodfillNetworkDatabaseFacade multiHomeNetDB() {
        if (!useSubDbs())
            return mainNetDB();
        return _multihomeDbid;
    }

    /**
     * get the client netDb for the given id
     * Will return the "exploratory(default client)" netDb if
     * the dbid is null.
     * 
     * @since 0.9.60
     * 
     */
    @Override
    public FloodfillNetworkDatabaseFacade clientNetDB(Hash id) {
        if (_log.shouldDebug())
            _log.debug("looked up clientNetDB: " + id);
        if (!useSubDbs())
            return mainNetDB();
        if (id != null){
            FloodfillNetworkDatabaseFacade fndf = getSubNetDB(id);
            if (fndf != null)
                return fndf;
        }
        return clientNetDB();
    }

    /**
     * get the default client(exploratory) netDb
     * 
     * @since 0.9.60
     * 
     */
    public FloodfillNetworkDatabaseFacade clientNetDB() {
        if (!useSubDbs())
            return mainNetDB();
        return _exploratoryDbid;
    }

    /**
     * look up the dbid of the client with the given signing public key
     * 
     * @since 0.9.60
     * 
     */
    @Override
    public List<Hash> lookupClientBySigningPublicKey(SigningPublicKey spk) {
        List<Hash> rv = new ArrayList<>();
        for (Hash subdb : getClients()) {
            FloodfillNetworkDatabaseFacade fndf = _context.clientManager().getClientFloodfillNetworkDatabaseFacade(subdb);
            if (fndf == null)
                continue;
            // if (subdb.startsWith("clients_"))
            // TODO: see if we can access only one subDb at a time when we need
            // to look up a client by SPK. We mostly need this for managing blinded
            // and encrypted keys in the Keyring Config UI page. See also
            // ConfigKeyringHelper
            BlindData bd = fndf.getBlindData(spk);
            if (bd != null) {
                rv.add(subdb);
            }
        }
        return rv;
    }

    /**
     * Return the dbid that is associated with the supplied client LS key
     *
     * @param clientKey The LS key of the subDb context
     * @since 0.9.60
     */
    private Hash matchDbid(Hash clientKey) {
        for (FloodfillNetworkDatabaseFacade subdb : getClientSubNetDBs()) {
            if (subdb.matchClientKey(clientKey))
                return subdb._dbid;
        }
        return null;
    }

    /**
     * get all the subDbs and return them in a Set.
     * 
     * @since 0.9.60
     * 
     */
    @Override
    public Set<FloodfillNetworkDatabaseFacade> getSubNetDBs() {
        if (!_mainDbid.isInitialized())
            return Collections.emptySet();
        Set<FloodfillNetworkDatabaseFacade> rv = new HashSet<>();
        if (!useSubDbs()) {
            rv.add(mainNetDB());
            return rv;
        }
        rv.add(mainNetDB());
        rv.add(multiHomeNetDB());
        rv.add(clientNetDB());
        rv.addAll(_context.clientManager().getClientFloodfillNetworkDatabaseFacades());
        return rv;
    }

    private Set<FloodfillNetworkDatabaseFacade> getClientSubNetDBs() {
        if (!_mainDbid.isInitialized())
            return Collections.emptySet();
        Set<FloodfillNetworkDatabaseFacade> rv = new HashSet<>();
        if (!useSubDbs()) {
            rv.add(mainNetDB());
            return rv;
        }
        rv.add(clientNetDB());
        rv.addAll(_context.clientManager().getClientFloodfillNetworkDatabaseFacades());
        return rv;
    }

    /**
     * list of the BlindData objects for all known clients
     * 
     * @since 0.9.60
     * 
     */
    @Override
    public List<BlindData> getLocalClientsBlindData() {
        List<BlindData> rv = new ArrayList<>();
        for (FloodfillNetworkDatabaseFacade subdb : getClientSubNetDBs()) {
            rv.addAll(subdb.getBlindData());
        }
        return rv;
    }
}
