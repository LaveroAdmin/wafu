# WAFU Firewall for LaveroAdmin

Web Application Firewall (WAF) management extension for LaveroAdmin.

## Installation

```bash
composer require laveroadmin/wafu
php artisan migrate
php artisan admin:import wafu
```

## Features

- Real-time security event log with threat inspection
- IP blocking & whitelist management
- Granular WAF firewall configuration
- Asynchronous logging via Laravel queues

## License

The MIT License (MIT).
