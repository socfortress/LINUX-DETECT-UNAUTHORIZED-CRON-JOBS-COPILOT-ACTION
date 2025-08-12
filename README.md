## Detect-Unauthorized-CronJobs.sh

This script scans for suspicious cron jobs and systemd timers that reference non-standard paths, providing a JSON-formatted output for integration with security tools like OSSEC/Wazuh.

### Overview

The `Detect-Unauthorized-CronJobs.sh` script identifies potential unauthorized or suspicious cron jobs and systemd timers by analyzing their configurations for references to non-standard directories. It outputs results in a standardized JSON format suitable for active response workflows.

### Script Details

#### Core Features

1. **Suspicious Path Detection**: Scans cron jobs and systemd timers for entries referencing `/tmp`, `/dev/shm`, or `/home`.
2. **JSON Output**: Generates a structured JSON report for integration with security tools.
3. **Logging Framework**: Provides detailed logs for script execution and findings.

### How the Script Works

#### Command Line Execution
```bash
./Detect-Unauthorized-CronJobs.sh
```

#### Parameters

| Parameter | Type | Default Value | Description |
|-----------|------|---------------|-------------|
| `ARLog`   | string | `/var/ossec/active-response/active-responses.log` | Path for active response JSON output |

#### Example Invocation

```bash
# Run the script
./Detect-Unauthorized-CronJobs.sh
```

### Script Execution Flow

#### 1. Initialization Phase
- Clears the active response log file.
- Logs the start of the script execution.

#### 2. Cron Job Scanning
- Scans cron files in `/etc/cron*` and `/var/spool/cron*`.
- Identifies entries referencing suspicious directories (`/tmp`, `/dev/shm`, `/home`).

#### 3. Systemd Timer Scanning
- Lists all systemd timers and their associated services.
- Checks `ExecStart` paths for references to suspicious directories.

#### 4. JSON Output Generation
- Formats findings into a JSON array.
- Writes the JSON result to the active response log.

#### 5. Completion Phase
- Logs the duration of the script execution.
- Outputs the final JSON result.

### JSON Output Format

#### Success Response
```json
{
  "timestamp": "2025-07-18T10:30:45.123Z",
  "host": "HOSTNAME",
  "action": "Detect-Unauthorized-CronJobs.sh",
  "data": [
    {
      "type": "cron",
      "entry": "*/5 * * * * /tmp/suspicious.sh",
      "reason": "Non-standard path in cron"
    },
    {
      "type": "systemd_timer",
      "entry": "example.service",
      "reason": "ExecStart in suspicious path: /tmp/example.sh"
    }
  ],
  "copilot_soar": true
}
```

#### Empty Response
If no suspicious entries are found:
```json
{
  "timestamp": "2025-07-18T10:30:45.123Z",
  "host": "HOSTNAME",
  "action": "Detect-Unauthorized-CronJobs.sh",
  "data": [],
  "copilot_soar": true
}
```

### Implementation Guidelines

#### Best Practices
- Run the script with appropriate permissions to access cron and systemd files.
- Validate the JSON output for compatibility with your security tools.
- Test the script in isolated environments before production use.

#### Security Considerations
- Ensure the script runs with minimal privileges.
- Validate all input paths to prevent injection attacks.
- Protect the active response log file from unauthorized access.

### Troubleshooting

#### Common Issues
1. **Permission Errors**: Ensure the script has read access to cron and systemd files.
2. **Empty Results**: Verify that the directories being scanned contain valid cron jobs or timers.
3. **Log File Issues**: Check write permissions for the active response log path.

#### Debugging
Enable verbose logging by reviewing the script's log output:
```bash
./Detect-Unauthorized-CronJobs.sh
```

### Contributing

When modifying this script:
1. Maintain the core logging and JSON output structure.
2. Follow Bash scripting best practices.
3. Document any additional functionality or parameters.
4. Test thoroughly in isolated environments.

## License

This template is provided as-is for security automation and incident response purposes.
