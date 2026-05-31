const { execSync } = require('child_process');

function sanitize(cmd) {
    // VULN-5: Incomplete sanitization – only removes ; | &
    return cmd.replace(/[;|&]/g, '');
}

function execute(cmd, input) {
    const safeCmd = sanitize(cmd);
    if (!safeCmd) return '';
    try {
        return execSync(safeCmd, { input, encoding: 'utf8' });
    } catch (e) {
        return '';
    }
}

module.exports = { execute };