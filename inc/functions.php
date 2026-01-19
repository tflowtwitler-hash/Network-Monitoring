<?php
    include 'connection.php';

    function getAllConnectedDevices()
    {
        exec("ip neigh | awk '{print $1, $3 ,$5}'", $output);
        $DBO = dbconnect();

        foreach ($output as $line) {
            $parts = explode(" ", $line);
            if (count($parts) >= 2) {
                $ip = $parts[0];
                $interface = $parts[1];
                $mac = $parts[2];
                // Vérifier si le device existe déjà
                $stmt = $DBO->prepare("SELECT COUNT(*) FROM devices WHERE ip = ? AND mac = ?");
                $stmt->execute([$ip, $mac]);
                $count = $stmt->fetchColumn();

                if ($count == 0) {
                    // Si n'existe pas, on insère
                    $insert = $DBO->prepare("INSERT INTO devices (ip, mac, interface) VALUES (?, ?, ?)");
                    $insert->execute([$ip, $mac, $interface]);
                }
            }
        }
    }
    function getCurrentConnectedDevices()
    {
        exec("iw dev wlan0 station dump | awk '/Station/ {print $2}'", $output);
        $DBO = dbconnect();
        $devices = [];

        foreach ($output as $mac) {
            // On cherche l'appareil par MAC
            $stmt = $DBO->prepare("SELECT ip, mac, nom FROM devices WHERE mac = ?");
            $stmt->execute([$mac]);
            $device = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($device) {
                // Si trouvé, on ajoute au tableau
                $devices[] = $device;
            } else {
                // Sinon, on peut ajouter juste le MAC si nécessaire
                $devices[] = [
                    'ip' => null,
                    'mac' => $mac,
                    'nom' => null
                ];
            }
        }

        return $devices;
    }

    /**
     * Check if an IP address is already blocked
     */
    function isIPBlocked($ip)
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            throw new InvalidArgumentException("Invalid IP address format: $ip");
        }

        $escapedIP = escapeshellarg($ip);
        $command = "sudo iptables -L FORWARD -n | grep $escapedIP";

        exec($command, $output, $returnCode);

        // If grep finds the IP, return code is 0
        return $returnCode === 0;
    }

    /**
     * Block an IP address using iptables
     * 
     * @param string $ip The IP address to block
     * @return array Result with success status and details
     */
    function blockConnectionForIP($ip)
    {
        // Validate IP address format
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return [
                'success' => false,
                'error' => 'Invalid IP address format',
                'ip' => $ip,
                'message' => 'Invalid IP address format',
                'output' => '',
                'returnCode' => -1
            ];
        }

        // Check if already blocked
        if (isIPBlocked($ip)) {
            return [
                'success' => false,
                'error' => 'IP address is already blocked',
                'ip' => $ip,
                'message' => "IP $ip is already blocked",
                'output' => '',
                'returnCode' => -1
            ];
        }

        // Escape IP for shell command
        $escapedIP = escapeshellarg($ip);

        // Execute iptables command with sudo
        $command = "sudo /sbin/iptables -A FORWARD -s $escapedIP -j DROP 2>&1";

        exec($command, $output, $returnCode);

        // Log the action
        logFirewallAction('block', $ip, $returnCode === 0);

        return [
            'success' => $returnCode === 0,
            'ip' => $ip,
            'output' => implode("\n", $output),
            'returnCode' => $returnCode,
            'message' => $returnCode === 0 ? "IP $ip successfully blocked" : "Failed to block IP $ip",
            'error' => $returnCode !== 0 ? implode("\n", $output) : null
        ];
    }

    /**
     * Unblock an IP address using iptables
     * 
     * @param string $ip The IP address to unblock
     * @return array Result with success status and details
     */
    function unblockConnectionForIP($ip)
    {
        // Validate IP address format
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return [
                'success' => false,
                'error' => 'Invalid IP address format',
                'ip' => $ip,
                'message' => 'Invalid IP address format',
                'output' => '',
                'returnCode' => -1
            ];
        }

        // Check if IP is actually blocked
        if (!isIPBlocked($ip)) {
            return [
                'success' => false,
                'error' => 'IP address is not blocked',
                'ip' => $ip,
                'message' => "IP $ip is not currently blocked",
                'output' => '',
                'returnCode' => -1
            ];
        }

        // Escape IP for shell command
        $escapedIP = escapeshellarg($ip);

        // Execute iptables command to remove the rule
        $command = "sudo /sbin/iptables -D FORWARD -s $escapedIP -j DROP 2>&1";

        exec($command, $output, $returnCode);

        // Log the action
        logFirewallAction('unblock', $ip, $returnCode === 0);

        return [
            'success' => $returnCode === 0,
            'ip' => $ip,
            'output' => implode("\n", $output),
            'returnCode' => $returnCode,
            'message' => $returnCode === 0 ? "IP $ip successfully unblocked" : "Failed to unblock IP $ip",
            'error' => $returnCode !== 0 ? implode("\n", $output) : null
        ];
    }

    /**
     * Check if an IP address is currently blocked
     * 
     * @param string $ip The IP address to check
     * @return bool True if blocked, false otherwise
     */


    /**
     * Get all currently blocked IP addresses
     * 
     * @return array List of blocked IPs with rule details
     */
    function getBlockedIPs()
    {
        $command = "sudo /sbin/iptables -L FORWARD -n --line-numbers 2>&1";

        exec($command, $output, $returnCode);

        if ($returnCode !== 0) {
            return [
                'success' => false,
                'error' => 'Failed to retrieve blocked IPs',
                'ips' => []
            ];
        }

        $blockedIPs = [];

        foreach ($output as $line) {
            // Parse lines that contain DROP rules with source IPs
            // Example: "1    DROP       all  --  192.168.1.100        0.0.0.0/0"
            if (preg_match('/^(\d+)\s+DROP\s+\w+\s+--\s+([\d\.]+)/', $line, $matches)) {
                $blockedIPs[] = [
                    'rule_number' => $matches[1],
                    'ip' => $matches[2]
                ];
            }
        }

        return [
            'success' => true,
            'ips' => $blockedIPs,
            'count' => count($blockedIPs)
        ];
    }

    /**
     * Log firewall actions to a file
     * 
     * @param string $action The action performed (block/unblock)
     * @param string $ip The IP address
     * @param bool $success Whether the action succeeded
     */
    function logFirewallAction($action, $ip, $success)
    {
        $logFile = __DIR__ . '/../logs/firewall.log';
        $logDir = dirname($logFile);

        // Create log directory if it doesn't exist
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }

        $timestamp = date('Y-m-d H:i:s');
        $status = $success ? 'SUCCESS' : 'FAILED';
        $user = $_SERVER['REMOTE_ADDR'] ?? 'CLI';

        $logMessage = "[$timestamp] $status - $action IP: $ip - Requested by: $user\n";

        file_put_contents($logFile, $logMessage, FILE_APPEND | LOCK_EX);
    }

    /**
     * Flush all iptables INPUT rules (use with caution!)
     * 
     * @return array Result with success status
     */
    function flushAllBlockedIPs()
    {
        $command = "sudo /sbin/iptables -F FORWARD 2>&1";

        exec($command, $output, $returnCode);

        logFirewallAction('flush_all', 'ALL', $returnCode === 0);

        return [
            'success' => $returnCode === 0,
            'message' => $returnCode === 0 ? 'All INPUT rules flushed' : 'Failed to flush rules',
            'output' => implode("\n", $output),
            'returnCode' => $returnCode
        ];
    }

    /**
     * Save current iptables rules to persist across reboots
     *
     * @return array Result with success status
     */
    function saveIPTablesRules()
    {
        // For Debian/Ubuntu systems
        $command = "sudo /sbin/iptables-save > /etc/iptables/rules.v4 2>&1";

        exec($command, $output, $returnCode);

        return [
            'success' => $returnCode === 0,
            'message' => $returnCode === 0 ? 'iptables rules saved' : 'Failed to save rules',
            'output' => implode("\n", $output),
            'returnCode' => $returnCode
        ];
    }

    /**
     * Get iptables statistics
     *
     * @return array Statistics about blocked connections
     */
    function getFirewallStats()
    {
        $command = "sudo /sbin/iptables -L FORWARD -n -v 2>&1";

        exec($command, $output, $returnCode);

        if ($returnCode !== 0) {
            return [
                'success' => false,
                'error' => 'Failed to retrieve statistics'
            ];
        }

        return [
            'success' => true,
            'output' => implode("\n", $output),
            'raw_data' => $output
        ];
}