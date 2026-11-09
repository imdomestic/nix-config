// Rex rejects AeroSpace's off-screen placement; use native app hiding instead.
ObjC.import('AppKit');

function run(argv) {
    const apps = $.NSRunningApplication.runningApplicationsWithBundleIdentifier('com.superlogical.rex');
    if (apps.count === 0) return;
    const app = apps.objectAtIndex(0);
    const visible = argv[0] === 'visible';
    if (visible && app.hidden) app.unhide;
    if (!visible && !app.hidden) app.hide;
}
