package net.i2p.router.web.helpers;

import net.i2p.router.web.HelperBase;

public class JettyMigrationHelper extends HelperBase{
    public static final String PROP_COMPLETE = "routerconsole.jettyMigrationComplete";
    public void complete() {
        _context.router().saveConfig(PROP_COMPLETE, "true");
    }
}
